#!/bin/bash
set -ex

image_name="elynn/nat64:latest"

GOOS=linux GOARCH=amd64 go build -o xlat cmd/main/main.go
mv ./xlat docker/
cd docker/
docker build $BUILD_ARGS -t $image_name .
docker push $image_name
rm ./xlat
