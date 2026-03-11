
---

# NetGuard

**NetGuard** is a web-based dashboard for monitoring and managing **iptables packet logging rules** on Linux. It provides a clean interface with toggle-based rule control, real-time log visualization, and persistent rule management.

The project is designed for **network monitoring, security analysis, and firewall visibility**, allowing users to observe packet activity directly from a modern dashboard.

![NetGuard Dashboard](/imgs/image.png)

**Demo Video**
[https://www.linkedin.com/posts/fmahadybd_cybersecurity-firewall-linux-ugcPost-7437482168299253760-TxBN](https://www.linkedin.com/posts/fmahadybd_cybersecurity-firewall-linux-ugcPost-7437482168299253760-TxBN)

---

# Features

* **Rule Toggle Control**
  Enable or disable logging rules individually using dashboard switches.

* **Predefined Rule Profiles (10 rules)**
  Includes commonly monitored traffic types such as HTTP, HTTPS, DNS, SSH, ICMP, and forwarded traffic.

* **Live Log Viewer**
  Real-time packet logs with color-coded fields and search filtering.

* **Real-time Monitoring**
  Automatic log refresh every **5 seconds** (configurable).

* **Rule Management**

  * Enable all rules with one click
  * Clear all rules with confirmation modal

* **Persistent Firewall State**

  * Rules saved to `/etc/iptables/rules.v4`
  * Application state saved to `/etc/iptables-manager-state.json`

* **Traffic Insights**
  Visual packet timeline and traffic distribution charts in the dashboard.

---

# Architecture Overview

NetGuard combines several components:

* **iptables** – packet filtering and logging
* **Flask** – backend API and dashboard server
* **JavaScript Dashboard** – real-time visualization
* **rsyslog** – log handling
* **logrotate** – log file rotation

Packet flow:

```
Network Traffic
       │
       ▼
iptables LOG Rules
       │
       ▼
/var/log/iptables.log
       │
       ▼
Flask Backend
       │
       ▼
Real-Time Web Dashboard
```

---

# Quick Start

### 1. Run setup script

Installs dependencies and configures logging.

```bash
sudo bash setup.sh
```

This will configure:

* Flask environment
* rsyslog logging for iptables
* log rotation

### 2. Start the web server

```bash
sudo python3 app.py
```

### 3. Open the dashboard

```
http://localhost:5000
```

---

# Rule Profiles

| Rule            | Chain   | Description                   |
| --------------- | ------- | ----------------------------- |
| All Incoming    | INPUT   | Logs every incoming packet    |
| All Outgoing    | OUTPUT  | Logs every outgoing packet    |
| All Forwarded   | FORWARD | Logs routed/forwarded packets |
| HTTP            | OUTPUT  | TCP port 80 traffic           |
| HTTPS           | OUTPUT  | TCP port 443 traffic          |
| DNS Queries     | OUTPUT  | UDP port 53 traffic           |
| SSH             | INPUT   | TCP port 22 connections       |
| ICMP / Ping     | INPUT   | All ICMP packets              |
| Dropped Packets | INPUT   | INVALID or dropped packets    |
| New Connections | INPUT   | New TCP SYN packets           |

---

# Run as a Service (Optional)

After running `setup.sh`, NetGuard can run as a **systemd service**.

Start service:

```bash
sudo systemctl start iptables-manager
```

Enable at boot:

```bash
sudo systemctl enable iptables-manager
```

Check status:

```bash
sudo systemctl status iptables-manager
```

View service logs:

```bash
sudo journalctl -u iptables-manager -f
```

---

# Important Notes

* NetGuard **must run as root** because `iptables` requires elevated privileges.
* LOG rules are inserted **before UFW rules** (position 1) to ensure packet visibility.
* The **LOG target does not block traffic** — it only records packet metadata.
* Packet logs are stored in:

```
/var/log/iptables.log
```

* Application state file:

```
/etc/iptables-manager-state.json
```

---

# Planned Features

Upcoming improvements:

* Custom firewall rule creation from the dashboard
* IP **blacklist / whitelist management**
* Advanced traffic analytics and anomaly detection
* AI-assisted packet classification
* Export logs for SIEM tools (Wazuh / ELK)

---

# License

Open-source project. Contributions and improvements are welcome.

---

If you want, I can also help you improve this README further by adding:

* **Badges (GitHub stars, license, Python version)**
* **Professional screenshots section**
* **Installation for Ubuntu/Debian/CentOS**
* **Contributing guidelines**
* **Security disclaimer**
---