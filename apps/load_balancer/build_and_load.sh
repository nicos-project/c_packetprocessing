#!/bin/bash

make clean && make && sudo ./init/load.sh restart lb.fw

# Turn on the interfaces so that the link comes up
# TODO: Is there a way to make this setting permanent so that we don't have to
# do this each time after reloading the firmware. With the old BSP
# on pikachu, we didn't need this
sudo nfp -m mac -e set port ifup 0 0
sudo nfp -m mac -e set port ifup 0 4

