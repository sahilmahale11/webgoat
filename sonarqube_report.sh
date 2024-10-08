#!/bin/bash

curl -u squ_de715a18ac0c010239d5fbb220e42fca00c1a21f: "http://52.91.14.200:9000/api/issues/search?projectKeys=org.owasp.webgoat:webgoat&p=1&ps=500" -o sonarqube_report.json

python3 convert_json_to_the_csv.py
