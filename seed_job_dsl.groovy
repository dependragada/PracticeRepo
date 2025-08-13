pipelineJob('drims-dev-output-driver-api-ci-cd') {
    description('Jenkins pipeline job for DRIMS output-driver API')
      definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('https://deepak_tewatia@bitbucket.org/drms-middleware/outputdriver.git')
                        credentials('abb6aa0c-c6c5-42a7-a154-1e78fdec9a58')
                    }
                    branches('**')
                    browser {
                        bitbucketWeb {
                            repoUrl('https://deepak_tewatia@bitbucket.org/drms-middleware/outputdriver.git')
                        }
                    }
                     extensions {
                         //Add the Clean before checkout extension
                        cleanBeforeCheckout()
                    }
                }
            }
            scriptPath('Jenkinsfile')
        }
    }
}
