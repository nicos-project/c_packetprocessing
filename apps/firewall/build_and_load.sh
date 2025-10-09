#!/bin/bash

make clean && make && sudo ./init/load.sh restart firewall.fw
