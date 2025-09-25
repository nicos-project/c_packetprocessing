#!/bin/bash

make clean && make && sudo ./init/load.sh restart nat.fw
