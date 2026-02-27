What This Guarantees

✔ Captures on all interfaces (-i any)
✔ Full packets (-s 0)
✔ Rotates every MAX_SIZE_MB
✔ Stops exactly at midnight (-G seconds_until_midnight)
✔ File names include:

hostname_YYYY-MM-DD_HHMMSS.pcap

✔ Automatically restarts at date boundary

Example Output Files
server1_2026-02-27_000000.pcap
server1_2026-02-27_000000.pcap1
server1_2026-02-27_000000.pcap2
...
server1_2026-02-27_235959.pcap
Run It
chmod +x rolling-snoop.sh
sudo ./rolling-snoop.sh

Or as a systemd service (recommended for production).
