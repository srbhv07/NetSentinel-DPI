package com.packetanalyzer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.LongAdder;

final class DpiEngine {
    static final class Config {
        int loadBalancers = 2;
        int fastPathsPerLoadBalancer = 2;
        int queueSize = 10000;
        boolean verbose;
    }

    private static final class Envelope {
        static final Envelope POISON = new Envelope(-1, null, null, null);
        final long id;
        final PcapFile.Packet raw;
        final PacketParser.ParsedPacket parsed;
        final FiveTuple tuple;

        Envelope(long id, PcapFile.Packet raw, PacketParser.ParsedPacket parsed, FiveTuple tuple) {
            this.id = id;
            this.raw = raw;
            this.parsed = parsed;
            this.tuple = tuple;
        }

        boolean isPoison() {
            return raw == null;
        }
    }

    private static final class OutputItem {
        static final OutputItem POISON = new OutputItem(null, false);
        final Envelope packet;
        final boolean forward;

        OutputItem(Envelope packet, boolean forward) {
            this.packet = packet;
            this.forward = forward;
        }
    }

    private static final class Flow {
        AppType app = AppType.UNKNOWN;
        String domain = "";
        boolean classified;
        boolean blocked;
    }

    private static final class Stats {
        final LongAdder totalPackets = new LongAdder();
        final LongAdder totalBytes = new LongAdder();
        final LongAdder forwarded = new LongAdder();
        final LongAdder dropped = new LongAdder();
        final LongAdder tcpPackets = new LongAdder();
        final LongAdder udpPackets = new LongAdder();
        final LongAdder otherPackets = new LongAdder();
        final Map<AppType, Long> appCounts = new EnumMap<>(AppType.class);
        final ConcurrentMap<String, AppType> detectedDomains = new ConcurrentHashMap<>();

        synchronized void recordApp(AppType app, String domain) {
            appCounts.put(app, appCounts.getOrDefault(app, 0L) + 1L);
            if (domain != null && !domain.isEmpty()) detectedDomains.put(domain, app);
        }

        synchronized Map<AppType, Long> appCounts() {
            return new EnumMap<>(appCounts);
        }
    }

    private final Config config;
    private final RuleManager rules = new RuleManager();
    private final Stats stats = new Stats();

    DpiEngine(Config config) {
        if (config.loadBalancers < 1 || config.fastPathsPerLoadBalancer < 1 ||
                config.queueSize < 1 || config.loadBalancers * config.fastPathsPerLoadBalancer > 64) {
            throw new IllegalArgumentException("Thread counts must be positive and total fast paths must not exceed 64");
        }
        this.config = config;
    }

    RuleManager rules() {
        return rules;
    }

    boolean processFile(Path inputPath, Path outputPath) {
        if (inputPath.toAbsolutePath().normalize().equals(outputPath.toAbsolutePath().normalize())) {
            System.err.println("Input and output paths must be different.");
            return false;
        }
        try (PcapFile.Reader reader = new PcapFile.Reader(inputPath);
             PcapFile.Writer writer = new PcapFile.Writer(outputPath, reader.header())) {
            if (reader.header().network != 1) {
                System.err.println("Warning: PCAP link type " + reader.header().network +
                        " is not Ethernet; packet payload inspection may be unavailable.");
            }
            process(reader, writer);
            printReport();
            return true;
        } catch (IOException exception) {
            System.err.println("PCAP processing failed: " + exception.getMessage());
            return false;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            System.err.println("Processing was interrupted.");
            return false;
        }
    }

    private void process(PcapFile.Reader reader, PcapFile.Writer writer)
            throws IOException, InterruptedException {
        int totalFastPaths = config.loadBalancers * config.fastPathsPerLoadBalancer;
        List<BlockingQueue<Envelope>> lbQueues = new ArrayList<>();
        List<BlockingQueue<Envelope>> fpQueues = new ArrayList<>();
        List<AtomicLong> lbDispatched = new ArrayList<>();
        List<AtomicLong> fpProcessed = new ArrayList<>();
        List<ConcurrentMap<FiveTuple, Flow>> flows = new ArrayList<>();
        for (int i = 0; i < config.loadBalancers; i++) {
            lbQueues.add(new ArrayBlockingQueue<>(config.queueSize));
            lbDispatched.add(new AtomicLong());
        }
        for (int i = 0; i < totalFastPaths; i++) {
            fpQueues.add(new ArrayBlockingQueue<>(config.queueSize));
            fpProcessed.add(new AtomicLong());
            flows.add(new ConcurrentHashMap<>());
        }

        BlockingQueue<OutputItem> outputQueue = new ArrayBlockingQueue<>(config.queueSize);
        AtomicReference<IOException> outputFailure = new AtomicReference<>();
        AtomicReference<Throwable> workerFailure = new AtomicReference<>();
        Thread outputThread = new Thread(
                () -> runOutputWriter(outputQueue, totalFastPaths, writer, outputFailure),
                "pcap-output-writer");
        outputThread.start();

        List<Thread> fpThreads = new ArrayList<>();
        for (int fp = 0; fp < totalFastPaths; fp++) {
            final int fpId = fp;
            Thread thread = new Thread(() -> runFastPath(fpId, fpQueues.get(fpId), outputQueue,
                    flows.get(fpId), fpProcessed.get(fpId), workerFailure), "fast-path-" + fpId);
            fpThreads.add(thread);
            thread.start();
        }

        List<Thread> lbThreads = new ArrayList<>();
        for (int lb = 0; lb < config.loadBalancers; lb++) {
            final int lbId = lb;
            int firstFp = lb * config.fastPathsPerLoadBalancer;
            Thread thread = new Thread(() -> runLoadBalancer(lbId, firstFp, lbQueues.get(lbId),
                    fpQueues, lbDispatched.get(lbId), workerFailure), "load-balancer-" + lbId);
            lbThreads.add(thread);
            thread.start();
        }

        IOException readFailure = null;
        long packetId = 0;
        try {
            PcapFile.Packet raw;
            while ((raw = reader.readPacket()) != null) {
                PacketParser.ParsedPacket parsed = reader.header().network == 1
                        ? PacketParser.parse(raw.data) : new PacketParser.ParsedPacket();
                FiveTuple tuple = parsed.tuple();
                Envelope envelope = new Envelope(packetId++, raw, parsed, tuple);
                stats.totalPackets.increment();
                stats.totalBytes.add(raw.data.length);
                if (parsed.hasTcp) stats.tcpPackets.increment();
                else if (parsed.hasUdp) stats.udpPackets.increment();
                else stats.otherPackets.increment();
                int lb = Math.floorMod(tuple == null ? Long.hashCode(envelope.id) : tuple.hashCode(),
                        config.loadBalancers);
                lbQueues.get(lb).put(envelope);
            }
        } catch (IOException exception) {
            readFailure = exception;
        } finally {
            for (BlockingQueue<Envelope> queue : lbQueues) queue.put(Envelope.POISON);
        }

        joinAll(lbThreads);
        joinAll(fpThreads);
        outputThread.join();

        if (readFailure != null) throw readFailure;
        IOException writeFailure = outputFailure.get();
        if (writeFailure != null) throw writeFailure;
        Throwable processingFailure = workerFailure.get();
        if (processingFailure != null) {
            throw new IOException("A packet worker failed: " + processingFailure.getMessage(), processingFailure);
        }

        if (config.verbose) {
            System.out.println("Load balancer dispatch: " + counts(lbDispatched));
            System.out.println("Fast path processed:    " + counts(fpProcessed));
        }
    }

    private void runLoadBalancer(int lbId, int firstFp, BlockingQueue<Envelope> input,
                                 List<BlockingQueue<Envelope>> fpQueues, AtomicLong dispatched,
                                 AtomicReference<Throwable> failure) {
        try {
            while (true) {
                Envelope packet = input.take();
                if (packet.isPoison()) break;
                int fp = Math.floorMod(packet.tuple == null ? Long.hashCode(packet.id) : packet.tuple.hashCode(),
                        config.fastPathsPerLoadBalancer);
                fpQueues.get(firstFp + fp).put(packet);
                dispatched.incrementAndGet();
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            failure.compareAndSet(null, exception);
        } finally {
            for (int fp = 0; fp < config.fastPathsPerLoadBalancer; fp++) {
                putUninterruptibly(fpQueues.get(firstFp + fp), Envelope.POISON);
            }
        }
    }

    private void runFastPath(int fpId, BlockingQueue<Envelope> input, BlockingQueue<OutputItem> output,
                             ConcurrentMap<FiveTuple, Flow> flows, AtomicLong processed,
                             AtomicReference<Throwable> failure) {
        try {
            while (true) {
                Envelope packet = input.take();
                if (packet.isPoison()) break;
                processed.incrementAndGet();
                try {
                    boolean forward = inspect(packet, flows);
                    if (forward) stats.forwarded.increment();
                    else stats.dropped.increment();
                    output.put(new OutputItem(packet, forward));
                } catch (Throwable exception) {
                    failure.compareAndSet(null, exception);
                    stats.forwarded.increment();
                    output.put(new OutputItem(packet, true));
                }
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            failure.compareAndSet(null, exception);
        } finally {
            putUninterruptibly(output, OutputItem.POISON);
        }
    }

    private boolean inspect(Envelope packet, ConcurrentMap<FiveTuple, Flow> flows) {
        PacketParser.ParsedPacket parsed = packet.parsed;
        FiveTuple tuple = packet.tuple;
        AppType app = AppType.UNKNOWN;
        String domain = "";
        boolean blocked;
        if (tuple != null) {
            Flow flow = flows.computeIfAbsent(tuple, ignored -> new Flow());
            if (!flow.classified) classify(packet, flow);
            if (!flow.blocked) {
                RuleManager.BlockReason reason = rules.shouldBlock(tuple.sourceIp,
                        tuple.destinationPort, flow.app, flow.domain);
                flow.blocked = reason != null;
                if (flow.blocked && config.verbose) {
                    System.out.println("[drop] " + packet.id + " " + tuple +
                            " rule=" + reason.type + ":" + reason.detail);
                }
            }
            app = flow.app;
            domain = flow.domain;
            blocked = flow.blocked;
        } else {
            RuleManager.BlockReason reason = rules.shouldBlock(parsed.hasIp ? parsed.sourceIp : null,
                    -1, AppType.UNKNOWN, "");
            blocked = reason != null;
            if (blocked && config.verbose) {
                System.out.println("[drop] " + packet.id + " rule=" + reason.type + ":" + reason.detail);
            }
        }
        stats.recordApp(app, domain);
        return !blocked;
    }

    private static void classify(Envelope packet, Flow flow) {
        PacketParser.ParsedPacket parsed = packet.parsed;
        if (parsed.hasTcp && parsed.destinationPort == 443 && parsed.payloadLength > 5) {
            SniExtractor.tlsServerName(parsed.payload(packet.raw.data)).ifPresent(name -> {
                flow.domain = name;
                flow.app = AppType.classify(name);
                flow.classified = true;
            });
        }
        if (!flow.classified && parsed.hasTcp && parsed.destinationPort == 80 && parsed.payloadLength > 10) {
            SniExtractor.httpHost(parsed.payload(packet.raw.data)).ifPresent(host -> {
                flow.domain = host;
                flow.app = AppType.classify(host);
                flow.classified = true;
            });
        }
        if (!flow.classified && parsed.hasUdp &&
                (parsed.destinationPort == 53 || parsed.sourcePort == 53)) {
            flow.app = AppType.DNS;
            if (parsed.destinationPort == 53) {
                flow.domain = SniExtractor.dnsQuery(parsed.payload(packet.raw.data)).orElse("");
            }
            flow.classified = true;
        }
        if (!flow.classified && parsed.hasUdp && parsed.destinationPort == 443) {
            flow.app = AppType.QUIC;
            flow.classified = true;
        }
        if (!flow.classified) {
            if (parsed.destinationPort == 443) flow.app = AppType.HTTPS;
            else if (parsed.destinationPort == 80) flow.app = AppType.HTTP;
        }
    }

    private void runOutputWriter(BlockingQueue<OutputItem> queue, int expectedPoisons,
                                 PcapFile.Writer writer, AtomicReference<IOException> failure) {
        int poisons = 0;
        long nextPacketId = 0;
        TreeMap<Long, OutputItem> pending = new TreeMap<>();
        while (poisons < expectedPoisons) {
            OutputItem item;
            try {
                item = queue.take();
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                failure.compareAndSet(null, new IOException("Output writer was interrupted", exception));
                return;
            }
            if (item == OutputItem.POISON || item.packet == null) {
                poisons++;
                continue;
            }
            pending.put(item.packet.id, item);
            while (pending.containsKey(nextPacketId)) {
                OutputItem ready = pending.remove(nextPacketId++);
                if (config.verbose) {
                    System.out.println((ready.forward ? "[forward] packet " : "[drop] packet ") +
                            ready.packet.id);
                }
                if (!ready.forward || failure.get() != null) continue;
                try {
                    writer.write(ready.packet.raw);
                } catch (IOException exception) {
                    failure.compareAndSet(null, exception);
                }
            }
        }
    }

    private void printReport() {
        System.out.println();
        System.out.println("DPI processing report");
        System.out.println("---------------------");
        System.out.println("Total packets:     " + stats.totalPackets.sum());
        System.out.println("Total bytes:       " + stats.totalBytes.sum());
        System.out.println("TCP packets:       " + stats.tcpPackets.sum());
        System.out.println("UDP packets:       " + stats.udpPackets.sum());
        System.out.println("Other packets:     " + stats.otherPackets.sum());
        System.out.println("Forwarded packets: " + stats.forwarded.sum());
        System.out.println("Dropped packets:   " + stats.dropped.sum());
        System.out.println();
        System.out.println("Application breakdown:");
        List<Map.Entry<AppType, Long>> apps = new ArrayList<>(stats.appCounts().entrySet());
        apps.sort(Map.Entry.<AppType, Long>comparingByValue(Comparator.reverseOrder()));
        for (Map.Entry<AppType, Long> entry : apps) {
            System.out.printf("  %-14s %d%n", entry.getKey().displayName, entry.getValue());
        }
        if (!stats.detectedDomains.isEmpty()) {
            System.out.println();
            System.out.println("Detected domains/SNIs:");
            for (Map.Entry<String, AppType> entry : new TreeMap<>(stats.detectedDomains).entrySet()) {
                System.out.println("  " + entry.getKey() + " -> " + entry.getValue().displayName);
            }
        }
        System.out.println();
        System.out.printf("Rules loaded: %d IP, %d app, %d domain, %d port%n",
                rules.blockedIpCount(), rules.blockedAppCount(),
                rules.blockedDomainCount(), rules.blockedPortCount());
    }

    private static String counts(List<AtomicLong> values) {
        List<Long> counts = new ArrayList<>();
        for (AtomicLong value : values) counts.add(value.get());
        return counts.toString();
    }

    private static void joinAll(List<Thread> threads) throws InterruptedException {
        for (Thread thread : threads) thread.join();
    }

    private static <T> void putUninterruptibly(BlockingQueue<T> queue, T value) {
        boolean interrupted = false;
        while (true) {
            try {
                queue.put(value);
                break;
            } catch (InterruptedException exception) {
                interrupted = true;
            }
        }
        if (interrupted) Thread.currentThread().interrupt();
    }
}
