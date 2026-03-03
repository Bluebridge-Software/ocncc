#!/bin/sh

LOG_PATH=/IN/service_packages/CCS/tmp
TIMESTAMP=`date "+%Y%m%d%H%M%S"`

echo Processing file ${LOG_PATH}/${1}
nawk -f clientLog.nawk ${LOG_PATH}/${1}

cat clientLog_hdrs.csv clientLog_data.csv >> ${1}.${TIMESTAMP}
rm clientLog_hdrs.csv clientLog_data.csv

cat /dev/null > ${LOG_PATH}/${1}
