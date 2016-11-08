#!/bin/sh
make M=$PWD
sudo rmmod pcc_pacing
sudo insmod pcc_pacing.ko
sudo dmesg -C
sudo python test.py
