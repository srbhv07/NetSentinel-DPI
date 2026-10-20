package com.packetanalyzer;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

final class RuleManager {
    static final class BlockReason {
        final String type;
        final String detail;

        BlockReason(String type, String detail) {
            this.type = type;
            this.detail = detail;
        }
    }

    private final Set<String> blockedIps = ConcurrentHashMap.newKeySet();
    private final Set<AppType> blockedApps = ConcurrentHashMap.newKeySet();
    private final Set<String> blockedDomains = ConcurrentHashMap.newKeySet();
    private final Set<Integer> blockedPorts = ConcurrentHashMap.newKeySet();

    void blockIp(String address) {
        blockedIps.add(normalizeIp(address));
    }

    void blockApp(String name) {
        AppType app = AppType.fromName(name);
        if (app == null || app == AppType.UNKNOWN) {
            throw new IllegalArgumentException("Unknown application: " + name);
        }
        blockedApps.add(app);
    }

    void blockDomain(String domain) {
        String value = domain.trim().toLowerCase(Locale.ROOT);
        if (value.isEmpty()) throw new IllegalArgumentException("Domain rule cannot be empty");
        blockedDomains.add(value);
    }

    void blockPort(int port) {
        if (port < 0 || port > 65535) throw new IllegalArgumentException("Port must be between 0 and 65535");
        blockedPorts.add(port);
    }

    BlockReason shouldBlock(String sourceIp, int destinationPort, AppType app, String domain) {
        if (sourceIp != null && blockedIps.contains(sourceIp.toLowerCase(Locale.ROOT))) {
            return new BlockReason("IP", sourceIp);
        }
        if (blockedPorts.contains(destinationPort)) {
            return new BlockReason("PORT", Integer.toString(destinationPort));
        }
        if (blockedApps.contains(app)) {
            return new BlockReason("APP", app.displayName);
        }
        if (domain != null && !domain.isEmpty()) {
            String candidate = domain.toLowerCase(Locale.ROOT);
            for (String rule : blockedDomains) {
                if (matchesDomain(candidate, rule)) return new BlockReason("DOMAIN", domain);
            }
        }
        return null;
    }

    int blockedIpCount() {
        return blockedIps.size();
    }

    int blockedAppCount() {
        return blockedApps.size();
    }

    int blockedDomainCount() {
        return blockedDomains.size();
    }

    int blockedPortCount() {
        return blockedPorts.size();
    }

    void load(Path path) throws IOException {
        String section = "";
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) continue;
                if (line.startsWith("[") && line.endsWith("]")) {
                    section = line.toUpperCase(Locale.ROOT);
                    continue;
                }
                switch (section) {
                    case "[BLOCKED_IPS]":
                        blockIp(line);
                        break;
                    case "[BLOCKED_APPS]":
                        blockApp(line);
                        break;
                    case "[BLOCKED_DOMAINS]":
                        blockDomain(line);
                        break;
                    case "[BLOCKED_PORTS]":
                        blockPort(Integer.parseInt(line));
                        break;
                    default:
                        throw new IOException("Rule entry appears outside a supported section: " + line);
                }
            }
        } catch (IllegalArgumentException exception) {
            throw new IOException("Invalid rule in " + path + ": " + exception.getMessage(), exception);
        }
    }

    void save(Path path) throws IOException {
        try (BufferedWriter writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            writer.write("[BLOCKED_IPS]");
            writer.newLine();
            for (String ip : blockedIps) writeLine(writer, ip);
            writer.newLine();
            writer.write("[BLOCKED_APPS]");
            writer.newLine();
            for (AppType app : blockedApps) writeLine(writer, app.displayName);
            writer.newLine();
            writer.write("[BLOCKED_DOMAINS]");
            writer.newLine();
            for (String domain : blockedDomains) writeLine(writer, domain);
            writer.newLine();
            writer.write("[BLOCKED_PORTS]");
            writer.newLine();
            for (Integer port : blockedPorts) writeLine(writer, port.toString());
        }
    }

    private static void writeLine(BufferedWriter writer, String value) throws IOException {
        writer.write(value);
        writer.newLine();
    }

    private static boolean matchesDomain(String domain, String rule) {
        if (rule.indexOf('*') < 0) {
            return domain.contains(rule);
        }
        if (rule.startsWith("*.") && rule.indexOf('*', 1) < 0) {
            String base = rule.substring(2);
            return domain.equals(base) || domain.endsWith("." + base);
        }
        StringBuilder regex = new StringBuilder("^");
        for (int i = 0; i < rule.length(); i++) {
            char c = rule.charAt(i);
            if (c == '*') regex.append(".*");
            else regex.append(Pattern.quote(Character.toString(c)));
        }
        regex.append('$');
        return Pattern.matches(regex.toString(), domain);
    }

    private static String normalizeIp(String value) {
        String ip = value.trim();
        if (ip.indexOf(':') < 0) {
            String[] parts = ip.split("\\.", -1);
            if (parts.length != 4) throw new IllegalArgumentException("Invalid IP address: " + value);
            StringBuilder normalized = new StringBuilder();
            for (String part : parts) {
                int octet;
                try {
                    octet = Integer.parseInt(part);
                } catch (NumberFormatException exception) {
                    throw new IllegalArgumentException("Invalid IP address: " + value);
                }
                if (octet < 0 || octet > 255) throw new IllegalArgumentException("Invalid IP address: " + value);
                if (normalized.length() > 0) normalized.append('.');
                normalized.append(octet);
            }
            return normalized.toString();
        }
        if (!ip.matches("[0-9a-fA-F:.]+")) throw new IllegalArgumentException("Invalid IP address: " + value);
        try {
            InetAddress address = InetAddress.getByName(ip);
            if (address.getAddress().length != 16) throw new IllegalArgumentException("Invalid IPv6 address: " + value);
            return address.getHostAddress().toLowerCase(Locale.ROOT);
        } catch (UnknownHostException exception) {
            throw new IllegalArgumentException("Invalid IP address: " + value);
        }
    }
}
