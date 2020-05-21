#!/bin/bash
set -e
apt-get -y update; apt-get -y upgrade
apt-get install -y mysql-client
apt-get install -y python3
apt-get install -y zip
apt-get install -y python3-pip
pip3 install pydrive
cd "$(dirname "$0")"
echo "MYSQL dump Started"
id=`date +%y_%m_%d_%H_%M_%S`

sqlFile=mysql-$id.sql
zipFile=mysqldb-$id.zip
mysqldump --defaults-file=.my.cnf --all-databases -h database > $sqlFile
echo "Mysql dump completed"
echo "Archiving started"
zip  $zipFile $sqlFile 
echo "Archiving ended"
echo "Uploading and Deleting old files from Google Drive"
python3 upload_google_drive.py $zipFile
echo "Uploading and Deleting old files from Google Drive: SUCCESS"

