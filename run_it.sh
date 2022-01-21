#!/bin/env sh
docker run -it \
    --rm \
    --name stats_collect_srv_instance \
    --mount type=bind,src=$(pwd)/data,target=/data \
    -p 8080:8080 \
    stats_collect_srv
