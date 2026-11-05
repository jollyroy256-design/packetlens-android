# PacketLens: Android networking learning prototype

PacketLens is a small **offline** Android Java learning project for packet analysis concepts. It reads a bundled, synthetic Ethernet PCAP, decodes IPv4 TCP/UDP metadata and DNS queries, labels plaintext HTTP requests and TLS-port traffic, stores events in local SQLite, and shows a simple activity list.

## What it demonstrates

- Reading and validating a bounded PCAP file without collecting anyone's traffic.
- Extracting IP addresses, ports, TCP/UDP transport, DNS query names and plaintext HTTP request lines.
- Keeping parsed events in local SQLite and presenting counts plus a readable list in an Android Activity.
- Testing parser behavior with a generated three-packet sample and a malformed file.

## Honest limits

This is a **learning prototype**, not an Android network monitor. It does not capture live traffic, use `VpnService`, forward packets, identify apps by UID, intercept TLS, bypass certificate pinning or inspect encrypted contents. The TLS label is based on port 443 only. It does not implement PCAPdroid, Frida, JADX, WebView instrumentation or tracker intelligence. The application should never be described as prior production Android experience.

## Build and test

Open this folder in Android Studio and install the Android 35 platform plus a matching build-tools package. The project uses Android Gradle Plugin 9.4.0; [Google's compatibility table](https://developer.android.com/build/releases/about-agp) lists Gradle 9.6.0 as its minimum version. The Gradle wrapper is included; run `gradlew.bat assembleDebug` on Windows.

On 5 November 2026, `assembleDebug` succeeded. The resulting APK is at `app/build/outputs/apk/debug/app-debug.apk`. It was installed on an Android emulator. The bundled sample loaded and the UI displayed three events: one DNS, one HTTP and one TLS-port event. A [screenshot](emulator-demo.png) records that view. This is emulator validation only; physical-device testing remains to be done.

The parser can be checked without Android tooling:

1. Run `python tools/make_sample.py`.
2. Compile `PacketEvent.java`, `PcapReader.java` and `tools/PcapReaderCheck.java` with a JDK.
3. Run `PcapReaderCheck app/src/main/assets/sample.pcap`.

The bundled sample is generated locally and contains only example.org addresses and synthetic packet metadata. PacketLens requests no Android networking or VPN permissions.

## Next engineering steps

To evolve this into a live device monitor, obtain explicit Android VPN consent, build a correctly forwarding `VpnService`, handle IPv6 and fragmented packets, map sockets to app UIDs, and add tests on physical devices. Those steps require dedicated implementation and cannot be inferred from this prototype.
