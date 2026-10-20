package com.packetanalyzer;

import java.io.IOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public final class PacketAnalyzer {
    private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static void main(String[] args) {
        try {
            int status = run(args);
            if (status != 0) System.exit(status);
        } catch (IllegalArgumentException exception) {
            System.err.println("Error: " + exception.getMessage());
            printUsage();
            System.exit(2);
        }
    }

    private static int run(String[] args) {
        if (args.length == 0 || hasHelp(args)) {
            printUsage();
            return args.length == 0 ? 2 : 0;
        }
        if (args[0].equalsIgnoreCase("dpi")) return runDpi(args);
        if (args[0].equalsIgnoreCase("analyze")) return runAnalyze(args, 1);
        return runAnalyze(args, 0);
    }

    private static int runAnalyze(String[] args, int offset) {
        if (args.length <= offset) {
            printUsage();
            return 2;
        }
        Path input = Paths.get(args[offset]);
        int limit = -1;
        if (args.length > offset + 1) {
            try {
                limit = Integer.parseInt(args[offset + 1]);
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException("max_packets must be an integer");
            }
        }
        int packetCount = 0;
        int parseErrors = 0;
        try (PcapFile.Reader reader = new PcapFile.Reader(input)) {
            printHeader(input, reader.header());
            if (reader.header().network != 1) {
                System.err.println("Warning: link type " + reader.header().network +
                        " is not Ethernet; packet summaries are limited.");
            }
            System.out.println("\n--- Reading packets ---");
            PcapFile.Packet raw;
            while ((limit == 0 || limit < 0 || packetCount < limit) && (raw = reader.readPacket()) != null) {
                packetCount++;
                PacketParser.ParsedPacket parsed = reader.header().network == 1
                        ? PacketParser.parse(raw.data) : new PacketParser.ParsedPacket();
                if (parsed.validEthernet) {
                    printPacket(raw, parsed, packetCount, reader.header().nanosecondTimestamps);
                } else {
                    System.err.println("Warning: Failed to parse packet #" + packetCount);
                    parseErrors++;
                }
            }
            if (limit > 0 && packetCount >= limit) {
                System.out.println("\n(Stopped after " + limit + " packets)");
            }
            System.out.println("\n====================================");
            System.out.println("Summary:");
            System.out.println("  Total packets read:  " + packetCount);
            System.out.println("  Parse errors:        " + parseErrors);
            System.out.println("====================================");
            return 0;
        } catch (IOException exception) {
            System.err.println("Could not read PCAP file: " + exception.getMessage());
            return 1;
        }
    }

    private static int runDpi(String[] args) {
        if (args.length < 3) {
            printUsage();
            return 2;
        }
        Path input = Paths.get(args[1]);
        Path output = Paths.get(args[2]);
        DpiEngine.Config config = new DpiEngine.Config();
        List<String> blockedIps = new ArrayList<>();
        List<String> blockedApps = new ArrayList<>();
        List<String> blockedDomains = new ArrayList<>();
        List<Integer> blockedPorts = new ArrayList<>();
        Path rulesPath = null;

        for (int i = 3; i < args.length; i++) {
            String option = args[i];
            switch (option) {
                case "--block-ip":
                    blockedIps.add(requireValue(args, ++i, option));
                    break;
                case "--block-app":
                    blockedApps.add(requireValue(args, ++i, option));
                    break;
                case "--block-domain":
                    blockedDomains.add(requireValue(args, ++i, option));
                    break;
                case "--block-port":
                    try {
                        blockedPorts.add(Integer.parseInt(requireValue(args, ++i, option)));
                    } catch (NumberFormatException exception) {
                        throw new IllegalArgumentException("--block-port requires a number");
                    }
                    break;
                case "--rules":
                    rulesPath = Paths.get(requireValue(args, ++i, option));
                    break;
                case "--lbs":
                    config.loadBalancers = parsePositive(requireValue(args, ++i, option), option);
                    break;
                case "--fps":
                    config.fastPathsPerLoadBalancer = parsePositive(requireValue(args, ++i, option), option);
                    break;
                case "--queue-size":
                    config.queueSize = parsePositive(requireValue(args, ++i, option), option);
                    break;
                case "--verbose":
                    config.verbose = true;
                    break;
                default:
                    throw new IllegalArgumentException("Unknown option: " + option);
            }
        }

        try {
            DpiEngine engine = new DpiEngine(config);
            if (rulesPath != null) engine.rules().load(rulesPath);
            for (String ip : blockedIps) engine.rules().blockIp(ip);
            for (String app : blockedApps) engine.rules().blockApp(app);
            for (String domain : blockedDomains) engine.rules().blockDomain(domain);
            for (Integer port : blockedPorts) engine.rules().blockPort(port);
            boolean success = engine.processFile(input, output);
            if (success) System.out.println("\nOutput written to: " + output);
            return success ? 0 : 1;
        } catch (IOException exception) {
            System.err.println("Could not load rules: " + exception.getMessage());
            return 1;
        }
    }

    private static int parsePositive(String value, String option) {
        try {
            int parsed = Integer.parseInt(value);
            if (parsed < 1) throw new IllegalArgumentException(option + " must be positive");
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(option + " requires a positive integer");
        }
    }

    private static String requireValue(String[] args, int index, String option) {
        if (index >= args.length) throw new IllegalArgumentException(option + " requires a value");
        return args[index];
    }

    private static boolean hasHelp(String[] args) {
        for (String arg : args) {
            if (arg.equals("--help") || arg.equals("-h")) return true;
        }
        return false;
    }

    private static void printHeader(Path input, PcapFile.Header header) {
        System.out.println("Opened PCAP file: " + input);
        System.out.println("  Version: " + header.major + "." + header.minor);
        System.out.println("  Snaplen: " + header.snapLength + " bytes");
        System.out.println("  Link type: " + header.network + (header.network == 1 ? " (Ethernet)" : ""));
    }

    private static void printPacket(PcapFile.Packet raw, PacketParser.ParsedPacket packet, int number,
                                    boolean nanosecondTimestamps) {
        long nanos = raw.subsecond * (nanosecondTimestamps ? 1L : 1_000L);
        long micros = nanosecondTimestamps ? raw.subsecond / 1_000L : raw.subsecond;
        LocalDateTime time = LocalDateTime.ofInstant(Instant.ofEpochSecond(raw.seconds, nanos),
                ZoneId.systemDefault());
        System.out.println("\n========== Packet #" + number + " ==========");
        System.out.printf("Time: %s.%06d%n", time.format(TIMESTAMP), micros);
        System.out.println("\n[Ethernet]");
        System.out.println("  Source MAC:      " + packet.sourceMac);
        System.out.println("  Destination MAC: " + packet.destinationMac);
        System.out.printf("  EtherType:       0x%04x%s%n", packet.etherType,
                packet.etherType == 0x0800 ? " (IPv4)" :
                        packet.etherType == 0x86dd ? " (IPv6)" :
                                packet.etherType == 0x0806 ? " (ARP)" : "");
        if (packet.hasIp) {
            System.out.println("\n[IPv" + packet.ipVersion + "]");
            System.out.println("  Source IP:      " + packet.sourceIp);
            System.out.println("  Destination IP: " + packet.destinationIp);
            System.out.println("  Protocol:       " + protocolName(packet.protocol));
            System.out.println("  TTL:            " + packet.ttl);
        }
        if (packet.hasTcp) {
            System.out.println("\n[TCP]");
            System.out.println("  Source Port:      " + packet.sourcePort);
            System.out.println("  Destination Port: " + packet.destinationPort);
            System.out.println("  Sequence Number:  " + packet.sequenceNumber);
            System.out.println("  Ack Number:       " + packet.acknowledgementNumber);
            System.out.println("  Flags:            " + PacketParser.tcpFlagsToString(packet.tcpFlags));
        } else if (packet.hasUdp) {
            System.out.println("\n[UDP]");
            System.out.println("  Source Port:      " + packet.sourcePort);
            System.out.println("  Destination Port: " + packet.destinationPort);
        }
        if (packet.payloadLength > 0) {
            System.out.println("\n[Payload]");
            System.out.println("  Length: " + packet.payloadLength + " bytes");
            System.out.print("  Preview: ");
            int length = Math.min(packet.payloadLength, 32);
            for (int i = 0; i < length; i++) {
                System.out.printf("%02x ", raw.data[packet.payloadOffset + i] & 0xff);
            }
            if (packet.payloadLength > 32) System.out.print("...");
            System.out.println();
        }
    }

    private static String protocolName(int protocol) {
        switch (protocol) {
            case 1: return "ICMP";
            case 6: return "TCP";
            case 17: return "UDP";
            default: return "Unknown(" + protocol + ")";
        }
    }

    private static void printUsage() {
        System.out.println("NetSentinel-DPI - Deep Packet Inspection & Traffic Control Engine");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java -jar netsentinel-dpi.jar analyze <input.pcap> [max_packets]");
        System.out.println("  java -jar netsentinel-dpi.jar dpi <input.pcap> <output.pcap> [options]");
        System.out.println();
        System.out.println("DPI options:");
        System.out.println("  --block-ip <ip>       Block packets from a source IP");
        System.out.println("  --block-app <app>     Block an app (YouTube, Facebook, GitHub, etc.)");
        System.out.println("  --block-domain <text> Block a matching domain; supports *.example.com");
        System.out.println("  --block-port <port>   Block a destination port");
        System.out.println("  --rules <file>        Load rules from a sectioned rules file");
        System.out.println("  --lbs <n>             Number of load balancer threads (default 2)");
        System.out.println("  --fps <n>             Fast-path threads per load balancer (default 2)");
        System.out.println("  --queue-size <n>      Capacity of each worker queue (default 10000)");
        System.out.println("  --verbose             Print per-packet actions and worker counts");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java -jar netsentinel-dpi.jar analyze test_dpi.pcap 10");
        System.out.println("  java -jar netsentinel-dpi.jar dpi test_dpi.pcap filtered.pcap --block-app YouTube");
    }

    private PacketAnalyzer() {
    }
}
