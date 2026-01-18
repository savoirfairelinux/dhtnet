pipeline {
    agent any
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
