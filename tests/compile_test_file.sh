#!/bin/sh

docker build -t pelfy-test-cross-compiler .
docker run --rm -v $(pwd)/obj:/obj pelfy-test-cross-compiler