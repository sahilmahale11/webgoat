#!/bin/bash

echo "Sending Dependency check security findings to Defectdojo"

curl -X POST "http://18.208.161.29:8080/api/v2/import-scan/" -H "accept: application/json" \
-H "Content-Type: multipart/form-data" -H "Authorization: Token fe25ca812187e8dbc11578bc679392e3d051b933" -F "scan_date=$(date +%F)"\
 -F "minimum_severity=Info" -F "active=true" -F "verified=true" -F "scan_type=Dependency Check Scan"\
 -F "file=@dependency-check-report.xml;type=text/xml" -F "engagement=4" -F "close_old_findings=false" -F "push_to_jira=false"


if [ $? -eq 0 ]
then
   echo -e "\nReport sent successfully"
else
   echo -e "\nFailed to sent report"
fi
