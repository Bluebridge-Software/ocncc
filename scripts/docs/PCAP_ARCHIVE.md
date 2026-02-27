Schedule Archive via Cron

Run at 00:10 daily:

10 0 * * * /path/to/pcap-archive.sh >> /var/log/pcap/archive.log 2>&1
3️⃣ Directory Structure After Archive
/var/log/pcap/
    server1_2026-02-28_000000.pcap
    server1_2026-02-28_000000.pcap1
    capture_errors.log
    archive/
        server1_2026-02-27.tar.gz
        server1_2026-02-26.tar.gz
🔐 Production Hardening Recommendations

Use a dedicated tcpdump user.

Mount capture disk with large inode count.

Monitor disk usage.

Consider filesystem with large file performance (XFS).

Add logrotate policy for capture logs.
