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
          sh './truffelhog_report.sh'
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
                        sh './dependency_check_report.sh'
            }
        }
    
    stage ('Static Code Analysis') {
      steps {
        withSonarQubeEnv('sonar') {
            sh 'mvn sonar:sonar'
            //sh 'mvn clean compile sonar:sonar -Dsonar.java.binaries=target/classes'
        }
      }
    }
    
    stage ('Build Application') {
      steps {
        sh 'mvn clean install -DskipTests'
    }
    }	  	  
   }  
}
