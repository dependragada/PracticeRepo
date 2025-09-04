def services = [
    [ 
        name: 'service-A', 
        repo: 'https://bitbucket.org/your-org/service-a.git', 
        branch: 'main',
        buildScript: '''
            echo "Building Service A..."
            mvn clean install
            touch fileA
        '''
    ],
    [ 
        name: 'service-B', 
        repo: 'https://bitbucket.org/your-org/service-b.git', 
        branch: 'develop',
        buildScript: '''
            echo "Deploying Service B..."
            npm install
            npm run build
            touch fileB
        '''
    ],
    [ 
        name: 'service-C', 
        repo: 'https://bitbucket.org/your-org/service-c.git', 
        branch: 'release',
        buildScript: '''
            echo "Testing Service C..."
            pytest tests/
            touch fileC
        '''
    ]
]

services.each { svc ->
    job("deploy-${svc.name}") {
        description("This Job is used to deploy ${svc.name}")

        // Restrict where this project can be run
        label('aws-cloud')

        // Source Code Management
        scm {
            git {
                remote {
                    url(svc.repo)
                    credentials('bitbucket-credentials-id') // Jenkins credentials ID
                }
                branch(svc.branch)
            }
        }

        // Build Triggers
        triggers {
            scm('H/15 * * * *') // poll SCM every 15 minutes
        }

        // Build Environment
        wrappers {
            preBuildCleanup()
        }

        // Build Steps
        steps {
            shell(svc.buildScript)
        }
    }
}
