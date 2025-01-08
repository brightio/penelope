#!/bin/bash

IMAGE_NAME="${IMAGE_NAME:-penelope}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

docker build -t "$IMAGE_NAME:$IMAGE_TAG" .

# Run using:
# docker run -it --privileged --rm -p 4444:4444 --volume ./.penelope/:/root/.penelope/ "$IMAGE_NAME:$IMAGE_TAG"
