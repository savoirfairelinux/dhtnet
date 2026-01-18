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
                    agent { label 'macOS' }
                    stages {
                        stage('Build') {
                            steps {
                                sh '''#!/bin/zsh -l
                                    alias docker=podman
                                    docker build -t dhtnet:${BUILD_ID} --target build .
                                '''
                            }
                        }
                        stage('Test') {
                            steps {
                                sh '''#!/bin/zsh -l
                                    docker build -t dhtnet-test:${BUILD_ID} --target test .
                                '''
                            }
                        }
                        stage('Extract Results') {
                            steps {
                                sh '''#!/bin/zsh -l
                                    container_id=$(docker create dhtnet-test:${BUILD_ID})
                                    docker cp $container_id:/result.summary result.summary
                                    docker cp $container_id:/coverage coverage
                                    docker rm -v $container_id
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
