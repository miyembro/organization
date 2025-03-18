pipeline {
    agent any

    environment {
        // You must set the following environment variables
        // ORGANIZATION_NAME
        // DOCKERHUB_USERNAME (it doesn't matter if you don't have one)
        SERVICE_NAME = "organization"
        IMAGE_NAME = "organization-miyembro"
        IMAGE_TAG = "${IMAGE_NAME}:${BUILD_NUMBER}"
        REPOSITORY_TAG = "${DOCKERHUB_USERNAME}/${IMAGE_TAG}"
        DOCKER_HUB_CREDS = credentials('miyembro-docker-token')  // Use the ID of your Docker Hub credentials
    }

    stages {
        stage('Preparation') {
            steps {
                cleanWs()  // Clean the workspace
                git credentialsId: 'GitHub', url: "https://github.com/${ORGANIZATION_NAME}/${SERVICE_NAME}", branch: 'main'  // Clone the repository
                sh 'chmod +x gradlew'  // Add execute permission to gradlew
            }
        }

        stage('Build') {
            steps {
                sh './gradlew clean build'  // Build the project using Gradle
            }
        }

        stage('Build and Push Image') {
            steps {
                script {

                    echo "REPOSITORY_TAG: ${REPOSITORY_TAG}"

                    echo "IMAGE_TAG: ${IMAGE_TAG}"

                    echo "IMAGE_NAME: ${IMAGE_NAME}"

                    // Authenticate with Docker Hub using the credentials
                    sh "echo ${DOCKER_HUB_CREDS_PSW} | docker login -u ${DOCKER_HUB_CREDS_USR} --password-stdin"

                    // Build the Docker image
                    sh "docker image build -t ${IMAGE_NAME} ."

                    // Tag the Docker image for the repository
                    sh "docker tag ${IMAGE_NAME} ${REPOSITORY_TAG}"

                    // Push the Docker image to Docker Hub
                    sh "docker push ${REPOSITORY_TAG}"
                }
            }
        }

        stage('Deploy to Cluster') {
            steps {
                sh 'envsubst < ${WORKSPACE}/deploy.yaml | kubectl apply -f -'  // Deploy to Kubernetes
            }
        }
    }
}