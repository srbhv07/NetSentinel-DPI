package com.packetanalyzer;

import java.net.InetAddress;
import java.net.UnknownHostException;

final class PacketParser {
    static final class ParsedPacket {
        boolean validEthernet;
        boolean hasIp;
        boolean hasTcp;
        boolean hasUdp;
        int ipVersion;
        int etherType;
        int protocol;
        int ttl;
        int sourcePort;
        int destinationPort;
        int tcpFlags;
        long sequenceNumber;
        long acknowledgementNumber;
        String sourceMac = "";
        String destinationMac = "";
        String sourceIp = "";
        String destinationIp = "";
        int payloadOffset;
        int payloadLength;

        FiveTuple tuple() {
            if (!hasIp || (!hasTcp && !hasUdp)) return null;
            return new FiveTuple(sourceIp, destinationIp, sourcePort, destinationPort, protocol);
        }

        byte[] payload(byte[] packet) {
            if (payloadOffset < 0 || payloadLength <= 0 || payloadOffset > packet.length) return new byte[0];
            int length = Math.min(payloadLength, packet.length - payloadOffset);
            byte[] result = new byte[length];
            System.arraycopy(packet, payloadOffset, result, 0, length);
            return result;
        }
    }

    static ParsedPacket parse(byte[] data) {
        ParsedPacket parsed = new ParsedPacket();
        if (data.length < 14) return parsed;
        parsed.validEthernet = true;
        parsed.destinationMac = macToString(data, 0);
        parsed.sourceMac = macToString(data, 6);
        int etherType = unsignedShort(data, 12);
        int offset = 14;
        while (etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100) {
            if (data.length < offset + 4) return parsed;
            etherType = unsignedShort(data, offset + 2);
            offset += 4;
        }
        parsed.etherType = etherType;
        if (etherType == 0x0800) {
            parseIpv4(data, offset, parsed);
        } else if (etherType == 0x86dd) {
            parseIpv6(data, offset, parsed);
        } else {
            parsed.payloadOffset = offset;
            parsed.payloadLength = Math.max(0, data.length - offset);
        }
        return parsed;
    }

    private static void parseIpv4(byte[] data, int offset, ParsedPacket parsed) {
        if (data.length < offset + 20) return;
        int versionIhl = data[offset] & 0xff;
        int ihl = (versionIhl & 0x0f) * 4;
        if ((versionIhl >>> 4) != 4 || ihl < 20 || data.length < offset + ihl) return;
        int totalLength = unsignedShort(data, offset + 2);
        if (totalLength != 0 && totalLength < ihl) return;
        int packetEnd = totalLength == 0 ? data.length : Math.min(data.length, offset + totalLength);
        parsed.hasIp = true;
        parsed.ipVersion = 4;
        parsed.ttl = data[offset + 8] & 0xff;
        parsed.protocol = data[offset + 9] & 0xff;
        parsed.sourceIp = ipv4ToString(data, offset + 12);
        parsed.destinationIp = ipv4ToString(data, offset + 16);
        int fragmentOffset = unsignedShort(data, offset + 6) & 0x1fff;
        int transportOffset = offset + ihl;
        if (fragmentOffset != 0) {
            parsed.payloadOffset = transportOffset;
            parsed.payloadLength = Math.max(0, packetEnd - transportOffset);
            return;
        }
        parseTransport(data, transportOffset, packetEnd, parsed);
    }

    private static void parseIpv6(byte[] data, int offset, ParsedPacket parsed) {
        if (data.length < offset + 40 || (data[offset] >>> 4 & 0x0f) != 6) return;
        int payloadLength = unsignedShort(data, offset + 4);
        int packetEnd = payloadLength == 0 ? data.length : Math.min(data.length, offset + 40 + payloadLength);
        parsed.hasIp = true;
        parsed.ipVersion = 6;
        parsed.ttl = data[offset + 7] & 0xff;
        parsed.sourceIp = ipv6ToString(data, offset + 8);
        parsed.destinationIp = ipv6ToString(data, offset + 24);
        int nextHeader = data[offset + 6] & 0xff;
        int transportOffset = offset + 40;
        while (isIpv6Extension(nextHeader)) {
            if (transportOffset + 2 > packetEnd) return;
            int followingHeader = data[transportOffset] & 0xff;
            int extensionLength;
            if (nextHeader == 44) {
                if (transportOffset + 8 > packetEnd) return;
                int fragmentOffset = (unsignedShort(data, transportOffset + 2) >>> 3) & 0x1fff;
                if (fragmentOffset != 0) {
                    parsed.protocol = followingHeader;
                    parsed.payloadOffset = transportOffset + 8;
                    parsed.payloadLength = Math.max(0, packetEnd - parsed.payloadOffset);
                    return;
                }
                extensionLength = 8;
            } else if (nextHeader == 51) {
                extensionLength = ((data[transportOffset + 1] & 0xff) + 2) * 4;
            } else {
                extensionLength = ((data[transportOffset + 1] & 0xff) + 1) * 8;
            }
            if (extensionLength < 8 || transportOffset + extensionLength > packetEnd) return;
            transportOffset += extensionLength;
            nextHeader = followingHeader;
        }
        parsed.protocol = nextHeader;
        parseTransport(data, transportOffset, packetEnd, parsed);
    }

    private static boolean isIpv6Extension(int nextHeader) {
        return nextHeader == 0 || nextHeader == 43 || nextHeader == 44 || nextHeader == 51 ||
                nextHeader == 60 || nextHeader == 135 || nextHeader == 139 || nextHeader == 140;
    }

    private static void parseTransport(byte[] data, int offset, int packetEnd, ParsedPacket parsed) {
        if (parsed.protocol == 6) {
            if (packetEnd < offset + 20) return;
            int headerLength = ((data[offset + 12] >>> 4) & 0x0f) * 4;
            if (headerLength < 20 || packetEnd < offset + headerLength) return;
            parsed.sourcePort = unsignedShort(data, offset);
            parsed.destinationPort = unsignedShort(data, offset + 2);
            parsed.sequenceNumber = unsignedInt(data, offset + 4);
            parsed.acknowledgementNumber = unsignedInt(data, offset + 8);
            parsed.tcpFlags = data[offset + 13] & 0xff;
            parsed.hasTcp = true;
            parsed.payloadOffset = offset + headerLength;
            parsed.payloadLength = Math.max(0, packetEnd - parsed.payloadOffset);
        } else if (parsed.protocol == 17) {
            if (packetEnd < offset + 8) return;
            parsed.sourcePort = unsignedShort(data, offset);
            parsed.destinationPort = unsignedShort(data, offset + 2);
            parsed.hasUdp = true;
            parsed.payloadOffset = offset + 8;
            int udpLength = unsignedShort(data, offset + 4);
            int udpEnd = udpLength >= 8 ? Math.min(packetEnd, offset + udpLength) : packetEnd;
            parsed.payloadLength = Math.max(0, udpEnd - parsed.payloadOffset);
        } else {
            parsed.payloadOffset = offset;
            parsed.payloadLength = Math.max(0, packetEnd - offset);
        }
    }

    static String macToString(byte[] data, int offset) {
        StringBuilder result = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) result.append(':');
            int value = data[offset + i] & 0xff;
            if (value < 16) result.append('0');
            result.append(Integer.toHexString(value));
        }
        return result.toString();
    }

    static String tcpFlagsToString(int flags) {
        StringBuilder result = new StringBuilder();
        appendFlag(result, flags, 0x02, "SYN");
        appendFlag(result, flags, 0x10, "ACK");
        appendFlag(result, flags, 0x01, "FIN");
        appendFlag(result, flags, 0x04, "RST");
        appendFlag(result, flags, 0x08, "PSH");
        appendFlag(result, flags, 0x20, "URG");
        return result.length() == 0 ? "none" : result.toString();
    }

    private static void appendFlag(StringBuilder result, int flags, int mask, String name) {
        if ((flags & mask) != 0) {
            if (result.length() > 0) result.append(' ');
            result.append(name);
        }
    }

    private static int unsignedShort(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
    }

    private static long unsignedInt(byte[] data, int offset) {
        return ((long) (data[offset] & 0xff) << 24) |
                ((long) (data[offset + 1] & 0xff) << 16) |
                ((long) (data[offset + 2] & 0xff) << 8) |
                (long) (data[offset + 3] & 0xff);
    }

    private static String ipv4ToString(byte[] data, int offset) {
        return (data[offset] & 0xff) + "." + (data[offset + 1] & 0xff) + "." +
                (data[offset + 2] & 0xff) + "." + (data[offset + 3] & 0xff);
    }

    private static String ipv6ToString(byte[] data, int offset) {
        try {
            return InetAddress.getByAddress(copyOfRange(data, offset, offset + 16)).getHostAddress();
        } catch (UnknownHostException impossible) {
            throw new IllegalArgumentException(impossible);
        }
    }

    private static byte[] copyOfRange(byte[] data, int from, int to) {
        byte[] copy = new byte[to - from];
        System.arraycopy(data, from, copy, 0, copy.length);
        return copy;
    }

    private PacketParser() {
    }
}
