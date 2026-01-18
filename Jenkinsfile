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
                        stage('SCM Checkout') {
                            steps {
                                checkout changelog: true, poll: false,
                                    scm: [$class: 'GitSCM',
                                        branches: [[name: 'FETCH_HEAD']],
                                        doGenerateSubmoduleConfigurations: false,
                                        extensions: [
                                            [$class: 'CloneOption', noTags: true, reference: '', shallow: true],
                                            [$class: 'WipeWorkspace']],
                                        submoduleCfg: [],
                                        userRemoteConfigs: [[refspec: '${GERRIT_REFSPEC}', url: 'https://${JAMI_GERRIT_URL}/dhtnet']]]
                            }
                        }
                        stage('Check Docker') {
                            steps {
                                sh '''
                                    if ! command -v docker &> /dev/null; then
                                        echo "Error: docker is not installed or not in PATH"
                                        exit 1
                                    fi
                                    echo "Docker found: $(docker --version)"
                                '''
                            }
                        }
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
                        stage('SCM Checkout') {
                            steps {
                                checkout changelog: true, poll: false,
                                    scm: [$class: 'GitSCM',
                                        branches: [[name: 'FETCH_HEAD']],
                                        doGenerateSubmoduleConfigurations: false,
                                        extensions: [
                                            [$class: 'CloneOption', noTags: true, reference: '', shallow: true],
                                            [$class: 'WipeWorkspace']],
                                        submoduleCfg: [],
                                        userRemoteConfigs: [[refspec: '${GERRIT_REFSPEC}', url: 'https://${JAMI_GERRIT_URL}/dhtnet']]]
                            }
                        }
                        stage('Check Podman') {
                            steps {
                                sh '''
                                    if ! command -v podman &> /dev/null; then
                                        echo "Error: podman is not installed or not in PATH"
                                        exit 1
                                    fi
                                    echo "Podman found: $(podman --version)"
                                '''
                            }
                        }
                        stage('Build') {
                            steps {
                                sh '''
                                    podman build -t dhtnet:${BUILD_ID} --target build .
                                '''
                            }
                        }
                        stage('Test') {
                            steps {
                                sh '''
                                    podman build -t dhtnet-test:${BUILD_ID} --target test .
                                '''
                            }
                        }
                        stage('Extract Results') {
                            steps {
                                sh '''
                                    export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"
                                    container_id=$(podman create dhtnet-test:${BUILD_ID})
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
