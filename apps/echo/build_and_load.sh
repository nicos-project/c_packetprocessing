#!/bin/bash

make clean && make && sudo ./init/load.sh restart echo.fw
