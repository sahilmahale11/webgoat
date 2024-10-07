import pandas as pd

# Load the Trufflehog scan report
trufflehog_report = pd.read_csv('truffelhog_output.csv')

# Load the Dependency Check report
dependency_check_report = pd.read_csv('dependency-check-report.csv')

# Load the SonarQube scan report
sonarqube_report = pd.read_csv('sonarqube_report.csv')

# Merge/concatenate the reports (modify based on how you want to combine them)
# You can concatenate if there are no common columns to merge on:
consolidated_report = pd.concat([trufflehog_report, dependency_check_report, sonarqube_report], axis=0, ignore_index=True)

# Alternatively, if there's a common column, e.g., 'file_name', you can merge based on that:
# consolidated_report = pd.merge(trufflehog_report, dependency_check_report, on='file_name', how='outer')
# consolidated_report = pd.merge(consolidated_report, sonarqube_report, on='file_name', how='outer')

# Save the consolidated report to a new CSV file
consolidated_report.to_csv('consolidated_report.csv', index=False)

print("Consolidation completed! Check the consolidated_report.csv file.")
