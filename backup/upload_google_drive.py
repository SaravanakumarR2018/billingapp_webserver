import sys
from datetime import datetime

from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive

size700KB = 700000
if len(sys.argv) != 2:
    print("Usage: upload_google_drive.py <file_path>")
def file_size(fname):
    import os
    statinfo = os.stat(fname)
    filesize = statinfo.st_size
    print(fname , " File size: ", filesize)
    if filesize < size700KB:
        print("File size less than 700 KB. exiting")
        sys.exit(1)
    return statinfo.st_size

file_size(sys.argv[1])
g_auth = GoogleAuth()
g_auth.CommandLineAuth()

drive = GoogleDrive(g_auth)

file2 = drive.CreateFile()
file2.SetContentFile(sys.argv[1])
file2.Upload()

file_list = drive.ListFile({'q': "'root' in parents and trashed=false"}).GetList()
mysql_file_list = []
for file in file_list:
    if 'mysqldb-' in file['title']:
        mysql_file_list.append(file)



def return_sort_key(file_data):
    timestamp = file_data['createdDate']
    datetime_obj = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%fZ')
    time = int(datetime_obj.timestamp())
    return time


total_files_preserved = 20
if len(mysql_file_list) <= 20:
    print("Number of mysql db files is %d less than %d", len(mysql_file_list), total_files_preserved)
    sys.exit(0)

mysql_file_list = sorted(mysql_file_list, key=return_sort_key, reverse=True)
for file in mysql_file_list:
    print("All files: ", file['title'], file['createdDate'])

mysql_file_list = mysql_file_list[total_files_preserved:]
for file in mysql_file_list:
    print("Files to be deleted: ", file['title'], file['createdDate'])

for file in mysql_file_list:
    print("Deleting file: ", file['title'], file['createdDate'])
    file1 = drive.CreateFile({'id': file['id']})
    file1.Trash()  # Move file to trash.
    file1.UnTrash()  # Move file out of trash.
    file1.Delete()  # Permanently delete the file.



