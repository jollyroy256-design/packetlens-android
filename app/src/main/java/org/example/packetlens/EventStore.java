package org.example.packetlens;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import java.util.ArrayList;
import java.util.List;

final class EventStore extends SQLiteOpenHelper {
    EventStore(Context context) { super(context, "packetlens.db", null, 1); }

    @Override public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, " +
                "protocol TEXT NOT NULL, source TEXT NOT NULL, destination TEXT NOT NULL, detail TEXT NOT NULL)");
    }
    @Override public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        throw new IllegalStateException("No migration defined");
    }
    void replace(List<PacketEvent> events) {
        SQLiteDatabase db = getWritableDatabase();
        db.beginTransaction();
        try {
            db.delete("events", null, null);
            for (PacketEvent event : events) {
                ContentValues values = new ContentValues();
                values.put("ts", event.timestampSeconds);
                values.put("protocol", event.protocol);
                values.put("source", event.source);
                values.put("destination", event.destination);
                values.put("detail", event.detail);
                db.insertOrThrow("events", null, values);
            }
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
    }
    List<PacketEvent> all() {
        List<PacketEvent> events = new ArrayList<>();
        try (Cursor c = getReadableDatabase().rawQuery(
                "SELECT ts, protocol, source, destination, detail FROM events ORDER BY id LIMIT 10000", null)) {
            while (c.moveToNext()) events.add(new PacketEvent(c.getLong(0), c.getString(1),
                    c.getString(2), c.getString(3), c.getString(4)));
        }
        return events;
    }
}
