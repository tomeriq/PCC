#! /bin/sh
sudo ethtool -K eth4 gso off
sudo ethtool -K eth4 tso off
sudo ethtool -K eth4 gro off
sudo sysctl -w net.core.default_qdisc=fq
sudo tc qdisc replace dev eth4 root fq pacing
sudo tc -s -d qdisc sh dev eth4
sudo sysctl -w net.core.wmem_max=16777216
sudo sysctl -w net.ipv4.tcp_wmem="4096 1684 16777216"
sudo sysctl -w net.core.rmem_max=25165824
sudo sysctl -w net.ipv4.tcp_wmem="4096 87380 25165824"
