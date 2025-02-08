#!/bin/bash

docker rm -f better-twitter
docker rmi backend:latest
./docker_build_image.sh
./docker_build_docker.sh
