pipeline {
  agent any 
  tools {
    maven 'Maven'
  }
  stages {
    stage ('Initialize') {
      steps {
        sh '''
                echo "PATH = ${PATH}"
                echo "M2_HOME = ${M2_HOME}"
            ''' 
      }
     }
    
    stage ('Secrets Scanner') {
      steps {
          sh 'trufflehog3 https://github.com/pentesty/DevSecOps_Acc.git -f json -o truffelhog_output.json || true'
          //sh './truffelhog_report.sh'
      }
    }
    
    stage ('Software Composition Analysis') {
            steps {
                dependencyCheck additionalArguments: ''' 
                    -o "./" 
                    -s "./"
                    -f "ALL" 
                    --prettyPrint''', odcInstallation: 'OWASP-DC'

                dependencyCheckPublisher pattern: 'dependency-check-report.xml'
                        //sh './dependency_check_report.sh'
            }
        }
    
    stage ('Static Code Analysis') {
      steps {
        withSonarQubeEnv('sonar') {
            sh 'mvn sonar:sonar'
            //sh 'mvn clean compile sonar:sonar -Dsonar.java.binaries=target/classes'
            sh './sonarqube_report.sh'
            sh 'cp consolidated_sonarqube_scan_output.csv "$PWD"/securitytoolsparser-main/output_files/stale_report/'
        }
      }
    }
    
    stage ('Build Application') {
      steps {
        sh 'mvn clean install -DskipTests'
    }
    }	  	 
    
    stage ('Incidents report') {
        steps {
	        sh 'echo "The Consolidated Final Report"'
	        sh 'cd securitytoolsparser-main/ && python3 run_parser.py -t "Trufflehog3 Scan" -p "../truffelhog_output.json" -o "consolidated_trufflehog_scan_output.csv"'
	        sh 'cd securitytoolsparser-main/ && python3 run_parser.py -t "DependencyCheck Scan" -p "../dependency-check-report.xml" -o "consolidated_dependency_check_output.csv"'
	        sh ''
        }
    }
   
   }  
}
