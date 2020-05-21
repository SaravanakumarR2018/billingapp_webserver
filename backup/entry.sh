#!/bin/sh
set -e
cd "$(dirname "$0")"
i=0
LOG_FILE="/root/script.log"

touch $LOG_FILE
exec 1>$LOG_FILE
exec 2>&1
apt-get -y update
apt-get -y upgrade
./scheduleTask.sh
i=1
wait_time=1440
while true; do
  echo Number: $i
  i=$((i+1))
  if test $((i%wait_time)) = 0; then
    echo "$i divisible by $wait_time."
    ./scheduleTask.sh
    i=1 
    echo Modified i: $i
  fi
  sleep 30
done
