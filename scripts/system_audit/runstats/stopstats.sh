#!/bin/sh

PID=`awk '{ print $1 }' ${1}/runstats.pid`
kill -INT ${PID}
rm ${1}/runstats.pid

