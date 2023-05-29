pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                mkdir Build
                cd Build
                cmake ..
                make
            }
        }
    }
}
