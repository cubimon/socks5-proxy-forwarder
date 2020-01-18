# Socks 5 forward proxy

Use this to manage your proxy servers - decide which proxy to use for which ip/domain name.
For maximum flexibility this is done by "Configuration as Code" in a python `proxy` function.
Work is based on [this socks5 python toy server](https://github.com/rushter/socks5).

- `request_handler`: socks5 proxy request handler, general class used to implement a proxy server
- `forwarder_server`: contains `proxy` function to proxy requests to other proxy servers dynamically
- `simple_server`: empty proxy function to resolve request from this machine and not chain to other proxies

My proxychains configuration file in `~/.proxychains/proxychains.conf`:

```ini
# resolve dns via proxy
proxy_dns

# no output, add this if your proxy works fine to not mess up stdout/sterr of the running program
#quiet_mode

[ProxyList]
socks5 127.0.0.1 1080
```

`.zprofile` or `.profile` file in home directory to always use proxychains through our socks5 proxy:

```bash
export PROXYCHAINS_CONF_FILE=/home/${username}/.proxychains/proxychains.conf
export LD_PRELOAD=/usr/lib/libproxychains4.so
```

alias to use proxy with sudo:

```bash
alias·sudoproxy="sudo·proxychains·-f·/home/${username}/.proxychains/proxychains.conf"
```

