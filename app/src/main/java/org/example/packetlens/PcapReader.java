package org.example.packetlens;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Bounded, offline PCAP reader. Ethernet/IPv4 TCP and UDP only. */
public final class PcapReader {
    private static final int MAX_CAPTURE_BYTES = 8 * 1024 * 1024;
    private static final int MAX_EVENTS = 10000;
    private PcapReader() {}

    public static List<PacketEvent> read(InputStream input) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int n;
        while ((n = input.read(chunk)) != -1) {
            if (out.size() + n > MAX_CAPTURE_BYTES) throw new IOException("PCAP is too large");
            out.write(chunk, 0, n);
        }
        byte[] data = out.toByteArray();
        if (data.length < 24) throw new IOException("Truncated PCAP header");
        int magic = ByteBuffer.wrap(data, 0, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        ByteOrder order;
        if (magic == 0xa1b2c3d4 || magic == 0xa1b23c4d) order = ByteOrder.BIG_ENDIAN;
        else if (magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1) order = ByteOrder.LITTLE_ENDIAN;
        else throw new IOException("Unsupported PCAP format");
        ByteBuffer b = ByteBuffer.wrap(data).order(order);
        int linkType = b.getInt(20);
        if (linkType != 1) throw new IOException("Only Ethernet PCAP is supported");
        List<PacketEvent> events = new ArrayList<>();
        int pos = 24;
        while (pos + 16 <= data.length && events.size() < MAX_EVENTS) {
            long seconds = Integer.toUnsignedLong(b.getInt(pos));
            long included = Integer.toUnsignedLong(b.getInt(pos + 8));
            pos += 16;
            if (included > data.length - pos) throw new IOException("Truncated packet");
            PacketEvent event = decode(data, pos, (int) included, seconds);
            if (event != null) events.add(event);
            pos += (int) included;
        }
        if (pos != data.length) throw new IOException("Trailing incomplete packet header");
        return events;
    }

    private static PacketEvent decode(byte[] d, int start, int length, long seconds) {
        int end = start + length;
        if (length < 34 || u16(d, start + 12) != 0x0800) return null;
        int ip = start + 14;
        if ((d[ip] & 0xf0) != 0x40) return null;
        int ihl = (d[ip] & 0x0f) * 4;
        if (ihl < 20 || ip + ihl > end) return null;
        int ipLength = u16(d, ip + 2);
        end = Math.min(end, ip + ipLength);
        int transport = ip + ihl;
        if (transport + 4 > end) return null;
        String src = address(d, ip + 12);
        String dst = address(d, ip + 16);
        int srcPort = u16(d, transport);
        int dstPort = u16(d, transport + 2);
        int protocol = d[ip + 9] & 0xff;
        String name;
        int payload;
        if (protocol == 17 && transport + 8 <= end) {
            name = "UDP";
            payload = transport + 8;
        } else if (protocol == 6 && transport + 20 <= end) {
            name = "TCP";
            payload = transport + ((d[transport + 12] >> 4) & 0xf) * 4;
            if (payload > end) return null;
        } else return null;
        String detail = "IP packet";
        if (protocol == 17 && (srcPort == 53 || dstPort == 53) && payload + 12 <= end) {
            name = "DNS";
            String q = dnsQuestion(d, payload, end);
            detail = q == null ? "DNS message" : "DNS query: " + q;
        } else if (protocol == 6 && payload < end && (srcPort == 80 || dstPort == 80)) {
            name = "HTTP";
            detail = asciiLine(d, payload, end);
        } else if (protocol == 6 && (srcPort == 443 || dstPort == 443)) {
            name = "TLS";
            detail = "TLS port 443 (encrypted payload not inspected)";
        }
        return new PacketEvent(seconds, name, src + ":" + srcPort, dst + ":" + dstPort, detail);
    }

    private static String dnsQuestion(byte[] d, int offset, int end) {
        int p = offset + 12;
        StringBuilder result = new StringBuilder();
        while (p < end) {
            int size = d[p++] & 0xff;
            if (size == 0) return result.length() == 0 ? null : result.toString();
            if (size > 63 || p + size > end) return null; // Reject compressed or malformed names.
            if (result.length() > 0) result.append('.');
            result.append(new String(d, p, size, StandardCharsets.US_ASCII));
            p += size;
        }
        return null;
    }

    private static String asciiLine(byte[] d, int offset, int end) {
        int stop = Math.min(end, offset + 120);
        int p = offset;
        while (p < stop && d[p] != '\r' && d[p] != '\n') p++;
        return new String(d, offset, p - offset, StandardCharsets.US_ASCII).replaceAll("[^\\x20-\\x7e]", "?");
    }

    private static int u16(byte[] d, int p) {
        return ((d[p] & 0xff) << 8) | (d[p + 1] & 0xff);
    }

    private static String address(byte[] d, int p) {
        return (d[p] & 0xff) + "." + (d[p + 1] & 0xff) + "." +
               (d[p + 2] & 0xff) + "." + (d[p + 3] & 0xff);
    }
}
