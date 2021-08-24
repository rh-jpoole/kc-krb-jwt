#!/bin/bash
SRC_DIR=$(pwd)/getcreds
podman build -v ${SRC_DIR}:/builderdir:z . --no-cache -t getcredsbuilder:dev
podman rmi localhost/getcredsbuilder:dev
