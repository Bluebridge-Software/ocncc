

RUNSTATS QUICKSTART GUIDE
=========================

Runstats includes a set of tools for gathering and compiling
system statistics while running tests.


1. Gathering statistics
=======================

To capture system statistics, copy the runstats scripts onto the target
machine.  Log in as root, and run the following command:

    ./runstats.sh

This will start a set of processes which gather statistics.  These run in
the background, controlled by the runstats script.  To stop capturing 
statistics, press CTRL-C to kill the processes.

A subdirectory named with a date/time stamp will be created.  This will 
contain all of the raw statistics data from the capture.


2. Compiling statistics
=======================

Once captured, the statistics data needs to be compiled into summary 
files.  These can subsequently be imported into spreadsheets for 
further detailed analysis.  To complete the compilation, run the 
following:

    ./compilestats.sh <subdir>

where <subdir> is the directory containing all of the statistics data.

For example:        # ./compilestats.sh 20110712153254


3. Capturing response times on the UAS
======================================

An extra utility has been included for gathering round-trip times on the
UAS machine.  This requires statistics to be turned on for the BeClient
debug output.

Ensure the following lines are included in the BeClient startup script:

    DEBUG=BE_BeClientIF_stat,BE_BeClientIF_stat_ack
    export DEBUG

Restart the SLEE.

Ensure that the BeClient log file is reset by running the following:

    cat /dev/null > BeClient.log (The og file may be different on your machine
    
Start your test.  Average round-trip times are output to the log file
When the test is finished, run the following script

    getClientTimes.sh <log file name>

The script assumes that the log file is located at /IN/service_packages/CCS/tmp.  
If it is not, edit the script to change the location, or remove the line
and enter the fill path on the command line.

The script will produce a file with a summary of turnaround time samples.
This will be the log file name with the date/time stamp appended.  This file
can be imported into a spreadsheet for further analysis.


4. Files produced by runstats
=============================
The following summarises the files produced by runstats

data_size.log               Shows the size of the sync and CDR diretories
oracle_snapshot.log         A full Oracle snaphot report for the test period
slee_queue.log              SLEE Queue sizes during the test period
vmstat.log                  Memory usage statistics
iostat_detail.log           Disk I/O raw data
prstat_detail.log           OS Process raw data
vxstat.log                  Veritas statistics (where Veritas is installed)
mpstat.log                  CPU Statistics
slee_free.log               SLEE Paramter statistics
oracle_ptree.log            Oracle process tree

5. Files produced by compilestats
=================================
iostat.csv                  Disk I/O Summary statistics
prstat.csv                  OS Process Summary Statistics
slee_queue.csv              SLEE Queue size summary statistics
summary_report.txt          A summary of statistics from prstat, iostat and slee_queue

