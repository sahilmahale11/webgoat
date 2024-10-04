#!/bin/bash

echo "Sending Truffelhog security findings to Defectdojo"

curl -X POST "http://44.202.248.61:8080/api/v2/import-scan/" -H "accept: application/json" \
-H "Content-Type: multipart/form-data" -H "Authorization: Token dbf34d236f2ca5d7260d62cf0ece98f6db3679d0" -F "scan_date=$(date +%F)"\
 -F "minimum_severity=Info" -F "active=true" -F "verified=true" -F "scan_type=Trufflehog3 Scan"\
 -F "file=@truffelhog_output.json" -F "engagement=4" -F "close_old_findings=false" -F "push_to_jira=false"

if [ $? -eq 0 ]
then
   echo -e "\nReport sent successfully"
else
   echo -e "\nFailed to sent report"
fi
