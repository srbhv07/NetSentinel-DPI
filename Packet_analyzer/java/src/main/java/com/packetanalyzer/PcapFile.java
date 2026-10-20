package com.packetanalyzer;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

final class PcapFile {
    private static final long MAX_PACKET_SIZE = 64L * 1024L * 1024L;

    static final class Header {
        final int major;
        final int minor;
        final int thisZone;
        final long sigFigs;
        final long snapLength;
        final long network;
        final ByteOrder byteOrder;
        final boolean nanosecondTimestamps;

        Header(int major, int minor, int thisZone, long sigFigs, long snapLength,
               long network, ByteOrder byteOrder, boolean nanosecondTimestamps) {
            this.major = major;
            this.minor = minor;
            this.thisZone = thisZone;
            this.sigFigs = sigFigs;
            this.snapLength = snapLength;
            this.network = network;
            this.byteOrder = byteOrder;
            this.nanosecondTimestamps = nanosecondTimestamps;
        }
    }

    static final class Packet {
        final long seconds;
        final long subsecond;
        final long originalLength;
        final byte[] data;

        Packet(long seconds, long subsecond, long originalLength, byte[] data) {
            this.seconds = seconds;
            this.subsecond = subsecond;
            this.originalLength = originalLength;
            this.data = data;
        }
    }

    static final class Reader implements Closeable {
        private final InputStream input;
        private final Header header;

        Reader(Path path) throws IOException {
            input = new BufferedInputStream(Files.newInputStream(path));
            boolean success = false;
            Header parsed;
            try {
                byte[] bytes = readExactly(input, 24);
                int magic = ByteBuffer.wrap(bytes, 0, 4).order(ByteOrder.BIG_ENDIAN).getInt();
                ByteOrder order;
                boolean nano;
                switch (magic) {
                    case 0xa1b2c3d4:
                        order = ByteOrder.BIG_ENDIAN;
                        nano = false;
                        break;
                    case 0xd4c3b2a1:
                        order = ByteOrder.LITTLE_ENDIAN;
                        nano = false;
                        break;
                    case 0xa1b23c4d:
                        order = ByteOrder.BIG_ENDIAN;
                        nano = true;
                        break;
                    case 0x4d3cb2a1:
                        order = ByteOrder.LITTLE_ENDIAN;
                        nano = true;
                        break;
                    default:
                        throw new IOException(String.format("Invalid PCAP magic number: 0x%08x", magic));
                }
                ByteBuffer buffer = ByteBuffer.wrap(bytes).order(order);
                buffer.getInt();
                int major = Short.toUnsignedInt(buffer.getShort());
                int minor = Short.toUnsignedInt(buffer.getShort());
                int thisZone = buffer.getInt();
                long sigFigs = Integer.toUnsignedLong(buffer.getInt());
                long snapLength = Integer.toUnsignedLong(buffer.getInt());
                long network = Integer.toUnsignedLong(buffer.getInt());
                parsed = new Header(major, minor, thisZone, sigFigs, snapLength, network, order, nano);
                success = true;
            } finally {
                if (!success) {
                    input.close();
                }
            }
            header = parsed;
        }

        Header header() {
            return header;
        }

        Packet readPacket() throws IOException {
            int first = input.read();
            if (first < 0) {
                return null;
            }
            byte[] remaining = readExactly(input, 15);
            byte[] packetHeader = new byte[16];
            packetHeader[0] = (byte) first;
            System.arraycopy(remaining, 0, packetHeader, 1, remaining.length);
            ByteBuffer buffer = ByteBuffer.wrap(packetHeader).order(header.byteOrder);
            long seconds = Integer.toUnsignedLong(buffer.getInt());
            long subsecond = Integer.toUnsignedLong(buffer.getInt());
            long includedLength = Integer.toUnsignedLong(buffer.getInt());
            long originalLength = Integer.toUnsignedLong(buffer.getInt());
            if (includedLength > MAX_PACKET_SIZE ||
                    (header.snapLength > 0 && includedLength > header.snapLength)) {
                throw new IOException("Invalid PCAP packet length: " + includedLength);
            }
            byte[] data = readExactly(input, (int) includedLength);
            return new Packet(seconds, subsecond, originalLength, data);
        }

        @Override
        public void close() throws IOException {
            input.close();
        }
    }

    static final class Writer implements Closeable {
        private final OutputStream output;
        private final Header header;

        Writer(Path path, Header header) throws IOException {
            this.header = header;
            output = new BufferedOutputStream(Files.newOutputStream(path));
            ByteBuffer buffer = ByteBuffer.allocate(24).order(header.byteOrder);
            int magic;
            if (header.nanosecondTimestamps) {
                magic = 0xa1b23c4d;
            } else {
                magic = 0xa1b2c3d4;
            }
            buffer.putInt(magic);
            buffer.putShort((short) header.major);
            buffer.putShort((short) header.minor);
            buffer.putInt(header.thisZone);
            buffer.putInt((int) header.sigFigs);
            buffer.putInt((int) header.snapLength);
            buffer.putInt((int) header.network);
            output.write(buffer.array());
        }

        synchronized void write(Packet packet) throws IOException {
            ByteBuffer buffer = ByteBuffer.allocate(16).order(header.byteOrder);
            buffer.putInt((int) packet.seconds);
            buffer.putInt((int) packet.subsecond);
            buffer.putInt(packet.data.length);
            buffer.putInt((int) packet.originalLength);
            output.write(buffer.array());
            output.write(packet.data);
        }

        @Override
        public void close() throws IOException {
            output.close();
        }
    }

    private static byte[] readExactly(InputStream input, int length) throws IOException {
        byte[] result = new byte[length];
        int offset = 0;
        while (offset < length) {
            int count = input.read(result, offset, length - offset);
            if (count < 0) {
                throw new EOFException("Unexpected end of PCAP file");
            }
            offset += count;
        }
        return result;
    }

    private PcapFile() {
    }
}
