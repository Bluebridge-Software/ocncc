#!/bin/sh

LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/IN/service_packages/SLEE/lib:/IN/service_packages/E2BE/lib:/IN/service_packages/SMS/lib:/usr/sfw/lib
export LD_LIBRARY_PATH

# definition of files and contents

ENVIRONMENT_LOG=environment.log
PRSTAT_DETAIL_LOG=prstat_detail.log
IOSTAT_DETAIL_LOG=iostat_detail.log
VMSTAT_LOG=vmstat.log
MPSTAT_LOG=mpstat.log
SLEE_QUEUE_LOG=slee_queue.log
SLEE_FREE_LOG=slee_free.log
ORACLE_SNAPSHOT_LOG=oracle_snapshot.log
ORACLE_PTREE_LOG=oracle_ptree.log
DATA_SIZE_LOG=data_size.log
VXSTAT_LOG=vxstat.log

REPORT_INTERVAL=5
PRSTAT_TOP=40

# commands to generate statistics

SLEE_CHECK=/IN/service_packages/SLEE/bin/check
VXPRINT=/usr/sbin/vxprint
PRTDIAG=/usr/sbin/prtdiag
IOSTAT=/usr/bin/iostat
PRSTAT=/usr/bin/prstat
VMSTAT=/usr/bin/vmstat
MPSTAT=/usr/bin/mpstat
UNAME=/usr/bin/uname
PKGINFO=/usr/bin/pkginfo
VXSTAT=/usr/sbin/vxstat

# working vars

CURRENTDIR=`pwd`
PRSTAT_DETAIL_PID=0
IOSTAT_DETAIL_PID=0
VMSTAT_PID=0
MPSTAT_PID=0
SLEE_FREE_PID=0
SLEE_QUEUE_PID=0
ORACLE_SNAPSHOT_STARTID=0
ORACLE_SNAPSHOT_STOPID=0
DO_ENVIRONMENT=0
DO_REPORTDIR=0
VXSTAT_PID=0

startOracleSnapshot() {
    rm -f tmp
    $ORACLE_HOME/bin/sqlplus -s perfstat/perfstat << EOF | awk '{if(NR==1)printf("%s",$1);}' > tmp
set head off pagesize 0 feedback off
exec statspack.snap;
select max(snap_id) from stats\$snapshot;
exit
EOF
    ORACLE_SNAPSHOT_STARTID=`cat tmp`
    rm -f tmp
}
   
stopOracleSnapshot() {
    rm -f tmp
    $ORACLE_HOME/bin/sqlplus -s perfstat/perfstat << EOF | awk '{if(NR==1)printf("%s",$1);}' > tmp
set head off pagesize 0 feedback off
exec statspack.snap;
select max(snap_id) from stats\$snapshot;
exit
EOF
    ORACLE_SNAPSHOT_STOPID=`cat tmp`
    rm -f tmp
}

reportOracleSnapshot() {
    $ORACLE_HOME/bin/sqlplus -s perfstat/perfstat << EOF > /dev/null
set head off pagesize 0 feedback off
@?/rdbms/admin/spreport
$ORACLE_SNAPSHOT_STARTID
$ORACLE_SNAPSHOT_STOPID
$ORACLE_SNAPSHOT_LOG
@?/rdbms/admin/sppurge
$ORACLE_SNAPSHOT_STARTID
$ORACLE_SNAPSHOT_STOPID
EOF
    rm -f sppurge.lis
}

trapFunc() {
    echo ""
    echo "Got interrupt!"
    
    if [ "${PRSTAT_DETAIL_PID}" != "0" ]; then
        echo "Stopping prstat detail collector ..."
        kill ${PRSTAT_DETAIL_PID}
    fi
    if [ "${IOSTAT_DETAIL_PID}" != "0" ]; then
        echo "Stopping iostat detail collector ..."
        kill ${IOSTAT_DETAIL_PID}
    fi
    if [ "${VMSTAT_PID}" != "0" ]; then
        echo "Stopping vmstat collector ..."
        kill ${VMSTAT_PID}
    fi
    if [ "${MPSTAT_PID}" != "0" ]; then
        echo "Stopping mpstat collector ..."
        kill ${MPSTAT_PID}
    fi
    if [ "${SLEE_FREE_PID}" != "0" ]; then
        echo "Stopping SLEE free collector ..."
        kill ${SLEE_FREE_PID}
    fi
    if [ "${SLEE_QUEUE_PID}" != "0" ]; then
        echo "Stopping SLEE queue collector ..."
        kill ${SLEE_QUEUE_PID}
    fi
    if [ "${VXSTAT_PID}" != "0" ]; then
        echo "Stopping vxstat collector ..."
        kill ${VXSTAT_PID}
    fi
    
    echo "Create Oracle snapshot report ..."
    stopOracleSnapshot
    reportOracleSnapshot

    echo "All done. Goodbye!"
    cd ${CURRENTDIR}
    exit 0
}

trap trapFunc INT TERM

# check ennvironment

if [ -z "$ORACLE_HOME" ]; then
    echo "ORACLE_HOME must be set to run this script!"
    exit 1
fi
if [ -z "$ORACLE_SID" ]; then
    echo "ORACLE_SID must be set to run this script!"
    exit 1
fi

# process arguments

set -- `getopt "ed" "$@"` || {
    echo "Usage: `basename $0` [-e] [basedir] [-d] [reportdir]" 1>&2
    exit 1
}
while :
do
    case "$1" in
    -e) DO_ENVIRONMENT=1 
        BASEDIR=$1 
        ;;
    -d) DO_REPORTDIR=1 ;;
    --) break ;;
    esac
    shift
done
shift
#BASEDIR=$1

# locate and create directory in which to store stats

if [ -z "$BASEDIR" ]; then
    echo "Setting base directory to" ${CURRENTDIR} "..."
    BASEDIR="."
else
    if [ ! -d ${BASEDIR} ]; then
        echo "Creating base directory" ${BASEDIR} "..."
        mkdir -p ${BASEDIR}
        STATUS=$?
        if [ "$STATUS" != "0" ]; then
            echo "Failed to create base directory" ${BASEDIR}
            echo "Exiting..."
            exit 1
        fi
    fi
fi
if [ ${DO_REPORTDIR} = "1" ]; then
    REPORTDIR=${1}
else
    REPORTDIR=`date "+%Y%m%d%H%M%S"`
fi

RUNDIR=${BASEDIR}/${REPORTDIR}

echo "Creating output directory" ${RUNDIR} "..."
mkdir -p ${RUNDIR}
STATUS=$?
if [ "$STATUS" != "0" ]; then
    echo "Failed to create directory" ${RUNDIR}
    echo "Exiting..."
    exit
fi
cd ${RUNDIR}

echo $$ > ./runstats.pid

# dump test environment log

if [ ${DO_ENVIRONMENT} = "1" ]; then
    echo "Dumping environment info ..."
    ${UNAME} -a > ${ENVIRONMENT_LOG}
    echo "" >> ${ENVIRONMENT_LOG}
    ${PRTDIAG} >> ${ENVIRONMENT_LOG}
    echo "" >> ${ENVIRONMENT_LOG}
    ${PKGINFO} -x >> ${ENVIRONMENT_LOG}
    echo "" >> ${ENVIRONMENT_LOG}
    ${VXPRINT} >> ${ENVIRONMENT_LOG}
fi

# dump oracle process ptrees

echo "Dumping oracle ptree info ..."
ps -A | grep oracle | awk '{print $1}' | while read i; do ptree $i >> ${ORACLE_PTREE_LOG}; done

# start oracle snaphot
echo "Start Oracle snapshot ..."
startOracleSnapshot

# kick off stat collector child processes

echo "Starting prstat detail collector ..."
${PRSTAT} -cmLn ${PRSTAT_TOP} ${REPORT_INTERVAL} > ${PRSTAT_DETAIL_LOG} &
PRSTAT_DETAIL_PID=$!  

echo "Starting iostat detail collector ..."
${IOSTAT} -xmnp ${REPORT_INTERVAL} > ${IOSTAT_DETAIL_LOG} &
IOSTAT_DETAIL_PID=$! 

echo "Starting vmstat collector ..."
${VMSTAT} ${REPORT_INTERVAL} > ${VMSTAT_LOG} &
VMSTAT_PID=$!

echo "Starting mpstat collector ..."
${MPSTAT} ${REPORT_INTERVAL} > ${MPSTAT_LOG} &
MPSTAT_PID=$!

echo "Starting SLEE free collector ..."
${SLEE_CHECK} -f ${REPORT_INTERVAL} > ${SLEE_FREE_LOG} &
SLEE_FREE_PID=$! 

echo "Starting SLEE queue collector ..."
${SLEE_CHECK} -q ${REPORT_INTERVAL} > ${SLEE_QUEUE_LOG} &
SLEE_QUEUE_PID=$! 

echo "Starting vxstat collector ..."
${VXSTAT} -g datadg -i${REPORT_INTERVAL} > ${VXSTAT_LOG} &
VXSTAT_PID=$!

echo "Startup complete. Use Ctrl-C to stop."
while true; do
    sleep ${REPORT_INTERVAL}
    du -sh /IN/service_packages/E2BE/sync/ >> ${DATA_SIZE_LOG}
    du -sh /IN/service_packages/E2BE/sync2/ >> ${DATA_SIZE_LOG}
    du -sh /IN/service_packages/E2BE/logs/CDR >> ${DATA_SIZE_LOG} 
    du -sh /IN/service_packages/E2BE/logs/CDR-out/ >> ${DATA_SIZE_LOG} 
    du -sh /IN/service_packages/E2BE/logs/CDR2 >> ${DATA_SIZE_LOG} 
    du -sh /IN/service_packages/E2BE/logs/CDR-out2/ >> ${DATA_SIZE_LOG} 
done

