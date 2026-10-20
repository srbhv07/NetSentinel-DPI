package com.packetanalyzer;

import java.util.Objects;

final class FiveTuple {
    final String sourceIp;
    final String destinationIp;
    final int sourcePort;
    final int destinationPort;
    final int protocol;

    FiveTuple(String sourceIp, String destinationIp, int sourcePort, int destinationPort, int protocol) {
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
    }

    FiveTuple reverse() {
        return new FiveTuple(destinationIp, sourceIp, destinationPort, sourcePort, protocol);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof FiveTuple)) return false;
        FiveTuple tuple = (FiveTuple) other;
        return sourcePort == tuple.sourcePort && destinationPort == tuple.destinationPort &&
                protocol == tuple.protocol && sourceIp.equals(tuple.sourceIp) &&
                destinationIp.equals(tuple.destinationIp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sourceIp, destinationIp, sourcePort, destinationPort, protocol);
    }

    @Override
    public String toString() {
        String name = protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : Integer.toString(protocol);
        return sourceIp + ":" + sourcePort + " -> " + destinationIp + ":" + destinationPort + " (" + name + ")";
    }
}
