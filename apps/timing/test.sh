#!/bin/bash

OP=$1
ME_ISLAND=i32.me0


if [[ -n "$1" ]] 
then
    echo "Doing $1 operation:"
else 
    echo "Provide an operation name as first arg"
    exit
fi

if [[ -n "$2" ]] 
then
    ME_ISLAND=$2
fi
mkdir -p time/cycle/$ME_ISLAND

NET_DIR=/opt/netronome/bin
echo "clean..."
make clean

echo "build..."
make

echo "unload..."
$NET_DIR/nfp-nffw unload

echo "load..."
$NET_DIR/nfp-nffw load timing.fw

# echo $($NET_DIR/nfp-reg mecsr:i32.me0.Mailbox{0..3})


breakpoint_reg=$($NET_DIR/nfp-reg mecsr:$ME_ISLAND.ctx_enables.Breakpoint)
while [ "$breakpoint_reg" != "mecsr:$ME_ISLAND.ctx_enables.Breakpoint=0x1" ]; do
    echo $breakpoint_reg
    sleep .5s
    breakpoint_reg=$($NET_DIR/nfp-reg mecsr:$ME_ISLAND.ctx_enables.Breakpoint)
done

echo "Writing times to file..."
$NET_DIR/nfp-rtsym -v _ctm32_times > time/cycle/"$ME_ISLAND"/ctm32_"$OP"_times.txt
$NET_DIR/nfp-rtsym -v _ctm33_times > time/cycle/"$ME_ISLAND"/ctm33_"$OP"_times.txt
$NET_DIR/nfp-rtsym -v _ctm34_times > time/cycle/"$ME_ISLAND"/ctm34_"$OP"_times.txt
$NET_DIR/nfp-rtsym -v _ctm35_times > time/cycle/"$ME_ISLAND"/ctm35_"$OP"_times.txt
$NET_DIR/nfp-rtsym -v _ctm36_times > time/cycle/"$ME_ISLAND"/ctm36_"$OP"_times.txt
$NET_DIR/nfp-rtsym -v _imem_times > time/cycle/"$ME_ISLAND"/imem_"$OP"_times.txt

$NET_DIR/nfp-rtsym -v _emem0_times > time/cycle/"$ME_ISLAND"/emem0_"$OP"_times.txt
$NET_DIR/nfp-rtsym -v _emem1_times > time/cycle/"$ME_ISLAND"/emem1_"$OP"_times.txt

# $NET_DIR/nfp-rtsym -v _emem0_times > time/cycle/"$ME_ISLAND"/emem0.cache_"$OP"_times.txt
# $NET_DIR/nfp-rtsym -v _emem1_times > time/cycle/"$ME_ISLAND"/emem1.cache_"$OP"_times.txt