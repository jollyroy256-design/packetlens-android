package org.example.packetlens;

import android.app.Activity;
import android.os.Bundle;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

/** Offline sample viewer; it never captures live device traffic. */
public final class MainActivity extends Activity {
    private EventStore store;
    private TextView summary;
    private ListView list;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        store = new EventStore(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);
        TextView title = new TextView(this);
        title.setText("PacketLens · offline PCAP study");
        title.setTextSize(23);
        root.addView(title);
        summary = new TextView(this);
        summary.setText("No events yet. Load the bundled sample capture.");
        root.addView(summary);
        Button load = new Button(this);
        load.setText("Load sample PCAP");
        load.setOnClickListener(v -> loadSample());
        root.addView(load);
        list = new ListView(this);
        root.addView(list, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        setContentView(root);
        showEvents(store.all());
    }

    private void loadSample() {
        try (InputStream in = getAssets().open("sample.pcap")) {
            List<PacketEvent> events = PcapReader.read(in);
            store.replace(events);
            showEvents(events);
        } catch (IOException e) {
            summary.setText("Could not read sample: " + e.getMessage());
        }
    }

    private void showEvents(List<PacketEvent> events) {
        long dns = events.stream().filter(e -> e.protocol.equals("DNS")).count();
        long http = events.stream().filter(e -> e.protocol.equals("HTTP")).count();
        long tls = events.stream().filter(e -> e.protocol.equals("TLS")).count();
        summary.setText(events.size() + " packets  ·  DNS " + dns + "  HTTP " + http + "  TLS " + tls);
        list.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, events));
    }
}
