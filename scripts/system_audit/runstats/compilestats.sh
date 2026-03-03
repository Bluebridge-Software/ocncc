#!/bin/sh

echo Compiling...
cd $1
set -x

nawk -f ../prstat_detail.nawk prstat_detail.log
nawk -f ../iostat_detail.nawk iostat_detail.log
nawk -f ../slee_queue.nawk    slee_queue.log

cat prstat_detail_hdrs.csv prstat_detail_data.csv > prstat.csv
cat iostat_detail_hdrs.csv iostat_detail_data.csv > iostat.csv
cat slee_queue_hdrs.csv    slee_queue_data.csv    > slee_queue.csv

cat prstat_summary.txt iostat_summary.txt slee_queue_summary.txt > summary_report.txt

rm prstat_detail_hdrs.csv
rm prstat_detail_data.csv
rm iostat_detail_hdrs.csv
rm iostat_detail_data.csv
rm slee_queue_hdrs.csv
rm slee_queue_data.csv
rm prstat_summary.txt
rm iostat_summary.txt
rm slee_queue_summary.txt

set +x
cd ..

echo All done.

