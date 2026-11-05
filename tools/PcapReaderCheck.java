import org.example.packetlens.PacketEvent;
import org.example.packetlens.PcapReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;

public final class PcapReaderCheck {
    public static void main(String[] args) throws Exception {
        List<PacketEvent> events;
        try (FileInputStream in = new FileInputStream(args[0])) {
            events = PcapReader.read(in);
        }
        if (events.size() != 3) throw new AssertionError("Expected three events");
        if (!events.get(0).protocol.equals("DNS") ||
                !events.get(0).detail.contains("example.org")) throw new AssertionError("DNS");
        if (!events.get(1).protocol.equals("HTTP") ||
                !events.get(1).detail.startsWith("GET /")) throw new AssertionError("HTTP");
        if (!events.get(2).protocol.equals("TLS")) throw new AssertionError("TLS");
        boolean rejected = false;
        try {
            PcapReader.read(new ByteArrayInputStream(new byte[]{1, 2, 3}));
        } catch (IOException expected) {
            rejected = true;
        }
        if (!rejected) throw new AssertionError("Truncated capture was accepted");
        System.out.println("PCAP parser checks passed: DNS, HTTP, TLS and malformed input");
    }
}
