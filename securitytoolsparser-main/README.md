# security tools parser 
This tool will parse the output of security tools and transform it into json/csv. 
The output json/csv could further be used for importing into other test/defect management tools (Ex -> Jira)

## Prerequisite:
1. Install Python3.7 or above, pip and java (openjdk 11.0.17)
2. Install dependency packages by running below command:
    $ pip3 install -r requirements.txt

## Some examples of security tools supported are:
1. TruffleHog3 scan
2. Zap Scan
3. Dependency checker
4. Sonarqube

Below is the high level structure of this tool and its related files location. 

- security_tools_parser 
  - lib
    - logger.py
    - security_tools_parser.py
  - test_tools
    - cis_audit.py
    - dependency_check.py
    - kubescape_scanning.py
    - sonarqube.py
    - trivy.py
    - truffle_hog3.py
    - zap_scan.py
  - README.md
  - run_parser.py
  - config.json
  - requirements.txt
  			

In addition to this, we will create logs and output_files folder in security_tools_parser folder and 
add output csv/json and log file at the runtime.

To add any new tool, we need to add parser in <tool_name>.py format in test_tools directory 
and add condition in run_parser method to execute based on commandline input.

config.json file have configurable params like:
	csv_headers
	cwe_url
	log_filename
	log_level

You can use below steps to run this tool:
-----------------
1. Open cmd prompt/console
2. Go to security_tools_parser directory. 
cmd> cd security_tools_parser

3. Run the tool
cmd> python run_parser.py -t <test> -p <test_output_file>

Example:
-----------------
Run below command to run the script and generate json output:

cmd> python run_parser.py -t "Trufflehog3 Scan" -p "D:\DevSecOps\truffelhog_output.json" 

cmd> python run_parser.py -t "Kubescape Scanning" -p "D:\DevSecOps\Kubescape\results.xml" 

cmd> python run_parser.py -t "ZAP Scan" -p "D:\DevSecOps\zap_report" -o "consolidated_test_output.csv"

cmd> python run_parser.py -t "Dependency Check Scan" -p "D:\DevSecOps\dependency-check-report.xml"

cmd> python run_parser.py -t "Trivy CIS scan" -p "D:\DevSecOps\Trivy_CIS_result.json"

cmd> python run_parser.py -t "Trivy scan" -p "D:\DevSecOps\Trivy_result.json" 

cmd> python run_parser.py -t "UBUNTU20-CIS-Audit" -p "D:\DevSecOps\cis_audit_UBUNTU2004.json" 

cmd> python run_parser.py -t "sonarqube" -u base_url -k project_key -b project_branch -a user_auth_key -o "consolidated_test_output.csv"

(run above command by replacing the parameters(i.e. base_url,project_key,project_branch,user_auth_key) with your actual parameters value)

Run below command to run the script to generate csv output:
cmd> python run_parser.py -t "Trufflehog3 Scan" -p "D:\DevSecOps\truffelhog_output.json" -o "consolidated_test_output.csv"
