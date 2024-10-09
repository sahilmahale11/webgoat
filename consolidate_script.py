import os
import pandas as pd

# Get the current working directory from the environment
current_directory = os.getenv('PWD')

# Define the file paths relative to the working directory
trufflehog_report_path = os.path.join(current_directory, 'securitytoolsparser-main', 'output_files', 'latest_report', 'consolidated_trufflehog_scan_output.csv')
dependency_check_report_path = os.path.join(current_directory, 'securitytoolsparser-main', 'output_files', 'latest_report', 'consolidated_dependency_check_output.csv')
sonarqube_report_path = os.path.join(current_directory, 'securitytoolsparser-main', 'output_files', 'latest_report', 'consolidated_sonarqube_scan_output.csv')

# Load the reports
trufflehog_report = pd.read_csv(trufflehog_report_path)
dependency_check_report = pd.read_csv(dependency_check_report_path)
sonarqube_report = pd.read_csv(sonarqube_report_path)

# Concatenate the reports (axis=0 means row-wise concatenation)
consolidated_report = pd.concat([trufflehog_report, dependency_check_report, sonarqube_report], axis=0, ignore_index=True)

# Save the consolidated report to a new CSV file
consolidated_report.to_csv(os.path.join(current_directory, 'Final_consolidated_scan_report.csv'), index=False)

print("Consolidation completed! Check the consolidated_report.csv file.")
