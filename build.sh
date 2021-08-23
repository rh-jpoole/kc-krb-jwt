#!/bin/bash
#export SRC_DIR=$(pwd)/gets3creds
podman build -v ${SRC_DIR}:/builderdir:z . --no-cache
