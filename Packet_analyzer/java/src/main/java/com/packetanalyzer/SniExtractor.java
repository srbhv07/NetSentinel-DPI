package com.packetanalyzer;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Optional;

final class SniExtractor {
    static Optional<String> tlsServerName(byte[] payload) {
        if (payload.length < 9 || (payload[0] & 0xff) != 0x16) return Optional.empty();
        int version = u16(payload, 1);
        if (version < 0x0300 || version > 0x0304) return Optional.empty();
        int recordLength = u16(payload, 3);
        if (recordLength > payload.length - 5 || (payload[5] & 0xff) != 1) return Optional.empty();
        int handshakeLength = u24(payload, 6);
        int handshakeEnd = Math.min(payload.length, 9 + handshakeLength);
        int offset = 9;
        if (offset + 34 > handshakeEnd) return Optional.empty();
        offset += 34; // Client version and random.
        if (offset >= handshakeEnd) return Optional.empty();
        int sessionLength = payload[offset++] & 0xff;
        offset = checkedAdvance(offset, sessionLength, handshakeEnd);
        if (offset < 0 || offset + 2 > handshakeEnd) return Optional.empty();
        int cipherLength = u16(payload, offset);
        offset = checkedAdvance(offset + 2, cipherLength, handshakeEnd);
        if (offset < 0 || offset >= handshakeEnd) return Optional.empty();
        int compressionLength = payload[offset++] & 0xff;
        offset = checkedAdvance(offset, compressionLength, handshakeEnd);
        if (offset < 0 || offset + 2 > handshakeEnd) return Optional.empty();
        int extensionsLength = u16(payload, offset);
        offset += 2;
        int extensionsEnd = Math.min(handshakeEnd, offset + extensionsLength);
        while (offset + 4 <= extensionsEnd) {
            int type = u16(payload, offset);
            int length = u16(payload, offset + 2);
            offset += 4;
            if (length > extensionsEnd - offset) return Optional.empty();
            if (type == 0 && length >= 5) {
                int listLength = u16(payload, offset);
                int nameType = payload[offset + 2] & 0xff;
                int nameLength = u16(payload, offset + 3);
                if (listLength >= 3 && nameType == 0 && nameLength > 0 && nameLength <= length - 5) {
                    String name = new String(payload, offset + 5, nameLength, StandardCharsets.US_ASCII).trim();
                    return name.isEmpty() ? Optional.empty() : Optional.of(name);
                }
            }
            offset += length;
        }
        return Optional.empty();
    }

    static Optional<String> httpHost(byte[] payload) {
        if (!looksLikeHttpRequest(payload)) return Optional.empty();
        String text = new String(payload, StandardCharsets.ISO_8859_1);
        int lineStart = text.indexOf('\n');
        if (lineStart < 0) return Optional.empty();
        int cursor = lineStart + 1;
        while (cursor < text.length()) {
            int end = text.indexOf('\n', cursor);
            if (end < 0) end = text.length();
            String line = text.substring(cursor, end).trim();
            if (line.isEmpty()) break;
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().toLowerCase(Locale.ROOT).equals("host")) {
                String host = line.substring(colon + 1).trim();
                if (host.startsWith("[")) {
                    int bracket = host.indexOf(']');
                    if (bracket > 0) host = host.substring(1, bracket);
                } else {
                    int portSeparator = host.lastIndexOf(':');
                    if (portSeparator > 0 && host.indexOf(':') == portSeparator) {
                        host = host.substring(0, portSeparator);
                    }
                }
                return host.isEmpty() ? Optional.empty() : Optional.of(host);
            }
            cursor = end + 1;
        }
        return Optional.empty();
    }

    static Optional<String> dnsQuery(byte[] payload) {
        if (payload.length < 17 || (payload[2] & 0x80) != 0 || u16(payload, 4) == 0) {
            return Optional.empty();
        }
        int offset = 12;
        StringBuilder domain = new StringBuilder();
        while (offset < payload.length) {
            int labelLength = payload[offset++] & 0xff;
            if (labelLength == 0) break;
            if (labelLength > 63 || labelLength > payload.length - offset) return Optional.empty();
            if (domain.length() > 0) domain.append('.');
            domain.append(new String(payload, offset, labelLength, StandardCharsets.US_ASCII));
            offset += labelLength;
        }
        return domain.length() == 0 ? Optional.empty() : Optional.of(domain.toString());
    }

    private static boolean looksLikeHttpRequest(byte[] payload) {
        String[] methods = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI", "CONN"};
        for (String method : methods) {
            byte[] bytes = method.getBytes(StandardCharsets.US_ASCII);
            if (payload.length < bytes.length) continue;
            boolean equal = true;
            for (int i = 0; i < bytes.length; i++) {
                if (payload[i] != bytes[i]) {
                    equal = false;
                    break;
                }
            }
            if (equal) return true;
        }
        return false;
    }

    private static int checkedAdvance(int offset, int count, int limit) {
        if (count < 0 || count > limit - offset) return -1;
        return offset + count;
    }

    private static int u16(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
    }

    private static int u24(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 16) | ((data[offset + 1] & 0xff) << 8) | (data[offset + 2] & 0xff);
    }

    private SniExtractor() {
    }
}
