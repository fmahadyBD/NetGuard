#  Net Guard

A beautiful web dashboard to manage iptables packet logging rules — with toggle switches, live log viewer, and persistent state.

## Features

- **Toggle switches** to enable/disable each logging rule individually
- **10 pre-built rule profiles**: All Input, All Output, HTTP, HTTPS, DNS, SSH, ICMP, Forwarded, Dropped, New Connections
- **Live log viewer** with color-coded packet info and real-time filtering
- **Clear all rules** button with confirmation modal
- **Enable all** with one click
- **Persist rules** to `/etc/iptables/rules.v4`
- **Auto-refresh** every 5 seconds
- State saved to `/etc/iptables-manager-state.json`

## Quick Start

```bash
# 1. Run setup (installs Flask, configures rsyslog, logrotate)
sudo bash setup.sh

# 2. Start the web server
sudo python3 app.py

# 3. Open in browser
http://localhost:5000
```

## Rule Profiles

| Rule | Chain | Description |
|------|-------|-------------|
| All Incoming | INPUT | Every incoming packet |
| All Outgoing | OUTPUT | Every outgoing packet |
| All Forwarded | FORWARD | Routed/forwarded packets |
| HTTP | OUTPUT | TCP port 80 |
| HTTPS | OUTPUT | TCP port 443 |
| DNS Queries | OUTPUT | UDP port 53 |
| SSH | INPUT | TCP port 22 |
| ICMP/Ping | INPUT | All ICMP packets |
| Dropped | INPUT | INVALID/dropped packets |
| New Connections | INPUT | New TCP SYN packets |


## Run as a Service (optional)

After setup.sh has been run:

```bash
sudo systemctl start iptables-manager    # start now
sudo systemctl enable iptables-manager   # start on boot
sudo systemctl status iptables-manager   # check status
sudo journalctl -u iptables-manager -f   # view logs
```

## Notes

- Must run as `root` (iptables requires root)
- LOG rules are inserted at position 1, before UFW rules
- The LOG target never drops packets — it only logs metadata
- Log file: `/var/log/iptables.log`
- State file: `/etc/iptables-manager-state.json`
