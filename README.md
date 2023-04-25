# Hackable Socks 5 forward proxy (Router/Proxy forwarding)

Use this to manage your proxy servers - decide which proxy to use for which ip/domain name.
For maximum flexibility this is done by "Configuration as Code" in a python `proxy` function.
Work is based on [this socks5 python toy server](https://github.com/rushter/socks5).
Additionally you may also route traffic through a specified network interface/bypass the routing table from python code by implementing a `router` function.
The last nice feature allows you to limit traffic to certain domains, e.g. netflix.com, or traffic generated by certain applications like youtube-dl.

## create socks5 proxy to host using ssh

`ssh -N -D ${portnumber} ${hostname}`

## File documentation
- `requesthandler`: socks5 proxy request handler, general class used to implement a proxy server.
- `proxyforwarderserver`: contains `proxy` function to proxy requests to other proxy servers dynamically.
- `simpleserver`: empty proxy function to resolve request from this machine and not chain to other proxies.
- `applicationbandwidthlimiter`: limit network traffic of curl/chrome/firefox. In addition implement a static routing table.
- `bandwidthmonitor` and `valve` are used to limit network traffic.
- `domain` to get ip address of domain
- `process` get process name from connection information
- `sit_vpn_proxy_forwarder` forwards connections to sit proxy if necessary
- `sit_vpn_docker_proxy_forwarder` forwards to proxy in docker to use vpn connection
- `sit_local_proxy_forwarder.py` same as vit_vpn_proxy_forwarder?

## Proxychains-ng

To force the use of this proxy for all/some applications you may use proxychains-ng.
My proxychains configuration file in `~/.proxychains/proxychains.conf` looks like this:

```ini
# resolve dns via proxy
proxy_dns

# no output, add this if your proxy works fine to not mess up stdout/sterr of the running program
#quiet_mode

[ProxyList]
socks5 127.0.0.1 1080
```

### Proxychains-ng for all applications

`.zprofile` or `.profile` file in home directory to always use proxychains through our socks5 proxy:

```bash
# default config file
#export PROXYCHAINS_CONF_FILE=/home/${username}/.proxychains/proxychains.conf
export LD_PRELOAD=/usr/lib/libproxychains4.so
```

### Proxychains-ng as sudo

```bash
alias·sudoproxy="sudo·proxychains·-f·/home/${username}/.proxychains/proxychains.conf"
```

### Proxychains-ng doesn't work for go applications

Use [graftcp](https://github.com/hmgle/graftcp), may also fully replace `proxychains-ng`?

### Proxychains-ng doesn't work for chrome/firefox

Set proxy manually in chrome/firefox settings.

