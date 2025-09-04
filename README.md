# EncapsulatedTLSHandshakeAnalysis

This project involves two Python scripts that pass pcap files through a V2Ray proxy to mimic network traffic, with the goal of determining whether the presence of the proxy can be detected. By comparing traffic before and after passing through the proxy, we aim to identify patterns indicative of proxy usage.

V2Ray: https://www.v2ray.com/en/

Pcap files: https://mawi.wide.ad.jp/mawi/

## Setting Up V2Ray
1. Install V2Ray on your machine
```
$ curl -o https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh
$ chmod +x install-release.sh
$ sudo ./install-release.sh
```
2. Place proxy_client.json, proxy_server.json, certificate.crt and private.key in /usr/local/etc/v2ray
3. Start the V2Ray proxy client and server services
```
$ sudo systemctl start v2ray@proxy_client
$ sudo systemctl start v2ray@proxy_server
```

## Test that V2Ray is set up correctly
1. Ensure that the V2Ray proxy client and server services are active and running
```
$ sudo systemctl status v2ray@proxy_client
$ sudo systemctl status v2ray@proxy_server
```
> The proxy can be deactivated at anytime by replacing 'status' with 'stop'.
2. Verify TLS certificate
```
$ curl -I --insecure https://localhost:1080
```
> Ports 1080 and 1081 should both have a TLS connection

## Passing traffic through the V2Ray proxy
1. Run the python scripts
```
$ sudo python3 replay_server.py
$ sudo python3 replay_client.py
```
> Ensure that these commands are run in this order and are running simultaneously
2. Collect traffic on ports 1080, 1081, and 1083
```
$ sudo tcpdump -i lo port 1080 -w 1080.pcap
$ sudo tcpdump -i lo port 1081 -w 1081.pcap
$ sudo tcpdump -i lo port 1083 -w 1083.pcap
```
> These commands can be run before running the scripts to get the initial TLS handshake as well.
3. Analyze pcap files in Wireshark
