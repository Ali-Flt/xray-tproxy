#!/bin/bash

cp ./config.json /etc/xray/config.json
cp ./nftables.conf /etc/nftables.conf
cp ./nftables.service /lib/systemd/system/nftables.service
systemctl daemon-reload
systemctl start xray
systemctl enable xray
systemctl start nftables.service
systemctl enable nftables.service


