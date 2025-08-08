pipelineJob('auto-deploy') {
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('https://github.com/rohitd260/DevOps.git')
                    }
                    branches('*/master')
                }
            }
            scriptPath('Jenkinsfile')
        }
    }
}
