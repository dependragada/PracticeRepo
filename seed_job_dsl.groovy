pipelineJob('drims-dev-output-driver-api-ci-cd') {
    description('Jenkins pipeline job for DRIMS output-driver API')
      definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('https://manav@bitbucket.org/drms-middleware/outputdriver.git')
                        credentials('35345436')
                    }
                    branches('**')
                    browser {
                        bitbucketWeb {
                            repoUrl('https://manav@bitbucket.org/drms-middleware/outputdriver.git')
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
