#!/bin/bash

# Default to echo if no argument provided
WORKER=${1:-echo}

# Validate the worker type
if [[ "$WORKER" != "echo" && "$WORKER" != "nat" ]]; then
    echo "Error: Invalid worker type '$WORKER'"
    echo "Usage: $0 [echo|nat]"
    exit 1
fi

echo "Building with WORKER=$WORKER"

make clean && make WORKER=$WORKER && sudo ./init/load.sh restart steer.fw

# Turn on the interfaces so that the link comes up
# TODO: Is there a way to make this setting permanent so that we don't have to
# do this each time after reloading the firmware. With the old BSP
# on pikachu, we didn't need this
sudo nfp -m mac -e set port ifup 0 0
sudo nfp -m mac -e set port ifup 0 4
