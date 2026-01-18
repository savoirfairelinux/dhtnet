pipeline {
    agent none
    triggers {
        gerrit customUrl: '',
            gerritProjects: [
                [branches: [[compareType: 'PLAIN', pattern: 'master']],
                 compareType: 'PLAIN',
                 disableStrictForbiddenFileVerification: false,
                 pattern: 'dhtnet']],
            triggerOnEvents: [
                commentAddedContains('!build'),
                patchsetCreated(excludeDrafts: true, excludeNoCodeChange: true)]
    }
    options {
        ansiColor('xterm')
    }
    parameters {
            string(name: 'GERRIT_REFSPEC',
                   defaultValue: 'refs/heads/dhtnet',
                   description: 'The Gerrit refspec to fetch.')
    }
    stages {
        stage('Build and Test') {
            parallel {
                stage('Linux') {
                    agent { label 'linux-builder' }
                    stages {
                        stage('Build') {
                            steps {
                                script {
                                    docker.build("dhtnet:${env.BUILD_ID}", "--target build .")
                                }
                            }
                        }
                        stage('Test') {
                            steps {
                                script {
                                    docker.build("dhtnet-test:${env.BUILD_ID}", "--target test .")
                                }
                            }
                        }
                        stage('Extract Results') {
                            steps {
                                sh """
                                    container_id=\$(docker create dhtnet-test:${env.BUILD_ID})
                                    docker cp \$container_id:/result.summary result.summary
                                    docker cp \$container_id:/coverage coverage
                                    docker rm -v \$container_id
                                    cat result.summary
                                """
                            }
                        }
                    }
                }
                stage('Mac') {
                    agent { label 'ios' }
                    stages {
                        stage('Build') {
                            steps {
                                sh '''
                                    export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"
                                    podman build --memory=24g -t dhtnet:${BUILD_ID} --target build .
                                '''
                            }
                        }
                        stage('Test') {
                            steps {
                                sh '''
                                    export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"
                                    podman build --memory=24g -t dhtnet-test:${BUILD_ID} --target test .
                                '''
                            }
                        }
                        stage('Extract Results') {
                            steps {
                                sh '''
                                    export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"
                                    container_id=$(docker create dhtnet-test:${BUILD_ID})
                                    podman cp $container_id:/result.summary result.summary
                                    podman cp $container_id:/coverage coverage
                                    podman rm -v $container_id
                                    cat result.summary
                                '''
                            }
                        }
                    }
                }
            }
        }
    }
}
