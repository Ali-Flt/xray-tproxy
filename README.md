# xray-tproxy
A transparent proxy based on the Tproxy documentation in Project X [here]([url](https://xtls.github.io/Xray-docs-next/en/document/level-2/tproxy.html)https://xtls.github.io/Xray-docs-next/en/document/level-2/tproxy.html).

# How to use
1. Install dependencies: `sudo pacman -S xray nftables iptables`
2. Edit `config.json` and replace the first outbound connection with your own. Also make sure to change all instances of `your.domain.name`, `your_uuid`, `put.your.ipv4.address`, ... elsewhere.
3. Copy `config.json` to `/etc/xray/`: `sudo cp config.json /etc/xray/config.json`
4. Copy the `nftables.conf` to `/etc`: `sudo cp nftables.conf /etc/nftables.conf`
5. Copy `nftables.service` to `/lib/systemd/system/`: `sudo cp nftables.service /lib/systemd/system/nftables.service`
6. Reload systemctl: `sudo systemctl daemon-reload`
7. Start and enable Xray service: `sudo systemctl start xray && sudo systemctl enable xray`
8. Start and enable nftables service: `sudo systemctl start nftables.service && sudo systemctl enable nftables.service`

Steps 3 to 8 can be done automatically using `sudo ./xray-tproxy.sh`
