pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                script {
                    docker.build("dhtnet:${env.BUILD_ID}", "--target build .")
                    sh "docker run -t --rm dhtnet:${env.BUILD_ID}"
                }
            }
        }
    }
}
