Design Overview:

We enumerate real interfaces dynamically (excluding lo by default).

Each interface runs its own dumpcap process.

Files are named:

hostname_YYYY-MM-DD_interface_HHMMSS_00001.pcap

A disk monitor loop:

Checks free space every 30 seconds

Stops all capture processes if free space < threshold

Important Notes

dumpcap filesize uses KB, not MB.

So:

50 MB = 50000 KB

We multiply by 1000 above to approximate 50MB.

Create Dedicated Capture User (Recommended)
sudo useradd -r -s /usr/sbin/nologin pcap
sudo chown -R pcap:pcap /var/log/pcap

Ensure dumpcap has capabilities:

sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

Verify:

getcap /usr/bin/dumpcap

Enable Service
sudo systemctl daemon-reload
sudo systemctl enable rolling-capture
sudo systemctl start rolling-capture

Check status:

sudo systemctl status rolling-capture

Resulting File Naming:
hostname_2026-02-27_000001.pcap
hostname_2026-02-27_000001_00001.pcap
hostname_2026-02-27_000001_00002.pcap
...

All files:

Rotate at 50MB

Stop at midnight

Never cross date boundary

Restart automatically

Archive Script Compatibility:

Your previous archive script works unchanged.

It will collect:

hostname_YYYY-MM-DD_*.pcap*

And compress them into:

hostname_YYYY-MM-DD.tar.gz
