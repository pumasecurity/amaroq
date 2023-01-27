#!/bin/bash
set -e

AWS_PUBLIC_ECR_ORG_URI=$1
RELEASE_VERSION=$2

# sign in to public ECR
aws ecr-public get-login-password | docker login --username AWS --password-stdin ${AWS_PUBLIC_ECR_ORG_URI}

# build image
docker image build --build-arg VERSION=${RELEASE_VERSION} --tag ${AWS_PUBLIC_ECR_ORG_URI}/amaroq:${RELEASE_VERSION} .
docker image tag ${AWS_PUBLIC_ECR_ORG_URI}/amaroq:${RELEASE_VERSION} ${AWS_PUBLIC_ECR_ORG_URI}/amaroq:latest

# push image + tags
docker image push --all-tags ${AWS_PUBLIC_ECR_ORG_URI}/amaroq

# sign image
cosign sign ${AWS_PUBLIC_ECR_ORG_URI}/amaroq:${RELEASE_VERSION}

# verify image
cosign verify -output json ${ECR_REPOSITORY_URI}:${RELEASE_VERSION}
