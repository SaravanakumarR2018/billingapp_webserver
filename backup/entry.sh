#!/bin/sh
set -e
LOG_FILE="/root/script.log"
touch $LOG_FILE
exec 1>$LOG_FILE
exec 2>&1
apt -y update
apt -y upgrade
apt install -y cron
service cron start
crontab /root/crontab.txt
while true; do sleep 30; df -h; done
