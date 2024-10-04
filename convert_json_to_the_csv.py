import json
import csv

# Load the JSON data
with open('sonarqube_report.json') as json_file:
    data = json.load(json_file)

# Create a CSV file
with open('sonarqube_report.csv', mode='w', newline='') as csv_file:
    fieldnames = ['key', 'severity', 'message', 'component', 'line']
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

    writer.writeheader()
    for issue in data['issues']:
        writer.writerow({
            'key': issue['key'],
            'severity': issue['severity'],
            'message': issue['message'],
            'component': issue['component'],
            'line': issue.get('line', 'N/A')
        })

print("Report saved as sonarqube_report.csv")
