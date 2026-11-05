package org.example.packetlens;

public final class PacketEvent {
    public final long timestampSeconds;
    public final String protocol;
    public final String source;
    public final String destination;
    public final String detail;

    public PacketEvent(long timestampSeconds, String protocol, String source,
                       String destination, String detail) {
        this.timestampSeconds = timestampSeconds;
        this.protocol = protocol;
        this.source = source;
        this.destination = destination;
        this.detail = detail;
    }

    @Override public String toString() {
        return protocol + "  " + source + " → " + destination + "\n" + detail;
    }
}
