#!/usr/bin/env python3
"""
NetGuard v2 — IPTables Log Manager
Production-ready network packet logging dashboard.
Run with: sudo python3 app.py
"""

from flask import Flask, jsonify, request, Response
import subprocess, os, json, time, re
from datetime import datetime, timezone
from collections import defaultdict

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
app        = Flask(__name__)
LOG_FILE   = "/var/log/iptables.log"
STATE_FILE = "/etc/netguard-state.json"
VERSION    = "2.0.0"

# ── Rule Profiles ──────────────────────────────────────────────────────────────
RULE_PROFILES = {
    "all_input":  {
        "id":"all_input","name":"All Inbound","short":"IN",
        "description":"Capture every inbound packet across all interfaces",
        "category":"Traffic","icon":"↙","color":"#22d3ee",
        "chain":"INPUT","position":1,"args":[],
        "prefix":"[IPTABLES INPUT] "
    },
    "all_output": {
        "id":"all_output","name":"All Outbound","short":"OUT",
        "description":"Capture every outbound packet across all interfaces",
        "category":"Traffic","icon":"↗","color":"#818cf8",
        "chain":"OUTPUT","position":1,"args":[],
        "prefix":"[IPTABLES OUTPUT] "
    },
    "all_forward":{
        "id":"all_forward","name":"Forwarded","short":"FWD",
        "description":"Capture all routed and forwarded packets",
        "category":"Traffic","icon":"⇄","color":"#fb923c",
        "chain":"FORWARD","position":1,"args":[],
        "prefix":"[IPTABLES FORWARD] "
    },
    "http": {
        "id":"http","name":"HTTP","short":"80",
        "description":"Log outbound HTTP traffic on TCP port 80",
        "category":"Web","icon":"◎","color":"#4ade80",
        "chain":"OUTPUT","position":1,
        "args":["-p","tcp","--dport","80"],
        "prefix":"[IPTABLES HTTP] "
    },
    "https": {
        "id":"https","name":"HTTPS","short":"443",
        "description":"Log outbound HTTPS/TLS traffic on TCP port 443",
        "category":"Web","icon":"◉","color":"#34d399",
        "chain":"OUTPUT","position":1,
        "args":["-p","tcp","--dport","443"],
        "prefix":"[IPTABLES HTTPS] "
    },
    "dns": {
        "id":"dns","name":"DNS","short":"53",
        "description":"Log all DNS resolution queries on UDP port 53",
        "category":"Web","icon":"⬡","color":"#fbbf24",
        "chain":"OUTPUT","position":1,
        "args":["-p","udp","--dport","53"],
        "prefix":"[IPTABLES DNS] "
    },
    "ssh": {
        "id":"ssh","name":"SSH","short":"22",
        "description":"Log inbound SSH connection attempts on TCP port 22",
        "category":"Access","icon":"⌥","color":"#f472b6",
        "chain":"INPUT","position":1,
        "args":["-p","tcp","--dport","22"],
        "prefix":"[IPTABLES SSH] "
    },
    "icmp": {
        "id":"icmp","name":"ICMP / Ping","short":"ICMP",
        "description":"Log all ICMP echo requests and replies",
        "category":"Access","icon":"◈","color":"#a78bfa",
        "chain":"INPUT","position":1,
        "args":["-p","icmp"],
        "prefix":"[IPTABLES ICMP] "
    },
    "new_connections":{
        "id":"new_connections","name":"New Connections","short":"SYN",
        "description":"Log new TCP SYN connection handshakes only",
        "category":"Access","icon":"⬢","color":"#38bdf8",
        "chain":"INPUT","position":1,
        "args":["-p","tcp","--syn"],
        "prefix":"[IPTABLES NEW] "
    },
    "dropped": {
        "id":"dropped","name":"Dropped / Invalid","short":"DROP",
        "description":"Log packets rejected due to invalid connection state",
        "category":"Security","icon":"⊗","color":"#f87171",
        "chain":"INPUT","position":None,
        "args":["-m","conntrack","--ctstate","INVALID"],
        "prefix":"[IPTABLES DROP] "
    },
}

TAG_COLOR = {
    "INPUT":"#22d3ee","OUTPUT":"#818cf8","FORWARD":"#fb923c",
    "HTTP":"#4ade80","HTTPS":"#34d399","DNS":"#fbbf24",
    "SSH":"#f472b6","ICMP":"#a78bfa","NEW":"#38bdf8","DROP":"#f87171",
}

# ── State helpers ──────────────────────────────────────────────────────────────
def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f: return json.load(f)
        except: pass
    return {k: False for k in RULE_PROFILES}

def save_state(state):
    try:
        with open(STATE_FILE,'w') as f: json.dump(state, f, indent=2)
    except Exception as e:
        print(f"[warn] state save: {e}")

# ── iptables helpers ───────────────────────────────────────────────────────────
def run_ipt(args):
    try:
        r = subprocess.run(["iptables"]+args, capture_output=True, text=True)
        return r.returncode==0, r.stdout+r.stderr
    except Exception as e:
        return False, str(e)

def rule_exists(p):
    _, out = run_ipt(["-L", p["chain"], "-n", "--line-numbers"])
    return p["prefix"].strip() in out

def add_rule(p):
    cmd = (["-I",p["chain"],str(p["position"])] if p["position"] else ["-A",p["chain"]])
    cmd += p["args"]+["-j","LOG","--log-prefix",p["prefix"],"--log-level","4"]
    return run_ipt(cmd)

def remove_rule(p):
    cmd = ["-D",p["chain"]]+p["args"]+["-j","LOG","--log-prefix",p["prefix"],"--log-level","4"]
    return run_ipt(cmd)

def clear_all_rules():
    removed = 0
    for chain in ["INPUT","OUTPUT","FORWARD"]:
        while True:
            _,out = run_ipt(["-L",chain,"-n","--line-numbers"])
            found = False
            for line in out.strip().split('\n'):
                if 'LOG' in line and '[IPTABLES' in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        run_ipt(["-D",chain,parts[0]])
                        removed += 1; found = True; break
            if not found: break
    return removed

def chain_counts():
    counts = {}
    for chain in ["INPUT","OUTPUT","FORWARD"]:
        _,out = run_ipt(["-L",chain,"-n","--line-numbers","-v"])
        counts[chain] = out.count("[IPTABLES")
    return counts

# ── Log reading ────────────────────────────────────────────────────────────────
def get_all_logs(n=2000):
    """Return up to n log lines, from file then journalctl fallback."""
    lines = []
    if os.path.exists(LOG_FILE):
        try:
            r = subprocess.run(["tail","-n",str(n),LOG_FILE], capture_output=True, text=True)
            lines = [l for l in r.stdout.strip().split("\n") if l.strip() and "IPTABLES" in l]
        except: pass
    if not lines:
        try:
            r = subprocess.run(
                ["journalctl","-k","--no-pager","-n",str(n),"--output=short-iso"],
                capture_output=True, text=True)
            lines = [l for l in r.stdout.strip().split("\n") if "IPTABLES" in l]
        except: pass
    return lines

def parse_tag(line):
    m = re.search(r'\[IPTABLES (\w+)\]', line)
    return m.group(1) if m else None

def tag_counts(lines):
    counts = defaultdict(int)
    for l in lines:
        t = parse_tag(l)
        if t: counts[t] += 1
    return dict(counts)

def activity_buckets(lines, buckets=40):
    """
    Split lines into `buckets` time-based buckets and count per bucket.
    Returns list of {label, count} dicts.
    """
    if not lines:
        return [{"label": str(i), "count": 0} for i in range(buckets)]

    # Parse timestamps from lines
    # Format: 2026-03-10T00:54:44.458719+06:00 or Mar 10 00:54:44
    timestamps = []
    for line in lines:
        # ISO format
        m = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
        if m:
            try:
                ts = datetime.fromisoformat(m.group(1)).timestamp()
                timestamps.append(ts)
                continue
            except: pass
        # syslog format: Mar 10 00:54:44
        m = re.match(r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
        if m:
            try:
                now = datetime.now()
                ts = datetime.strptime(f"{now.year} {m.group(1)}", "%Y %b %d %H:%M:%S").timestamp()
                timestamps.append(ts)
            except: pass

    if not timestamps:
        return [{"label": str(i), "count": 0} for i in range(buckets)]

    t_min, t_max = min(timestamps), max(timestamps)
    if t_max == t_min:
        result = [{"label": str(i), "count": 0} for i in range(buckets)]
        result[-1]["count"] = len(timestamps)
        return result

    bucket_size = (t_max - t_min) / buckets
    counts = [0] * buckets
    for ts in timestamps:
        idx = min(int((ts - t_min) / bucket_size), buckets - 1)
        counts[idx] += 1

    # Generate human-readable labels (HH:MM)
    result = []
    for i in range(buckets):
        t = t_min + i * bucket_size
        label = datetime.fromtimestamp(t).strftime("%H:%M")
        result.append({"label": label, "count": counts[i]})
    return result

# ── HTML ───────────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetGuard — IPTables Manager</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg0:#05070a;--bg1:#080c12;--bg2:#0c1018;--bg3:#101520;--bg4:#161d2a;--bg5:#1c2535;
  --line:rgba(255,255,255,0.06);--line2:rgba(255,255,255,0.10);
  --text:#e8edf5;--text2:#7a8899;--text3:#3d4d60;
  --cyan:#22d3ee;--indigo:#818cf8;--green:#4ade80;--amber:#fbbf24;
  --rose:#f87171;--violet:#a78bfa;--sky:#38bdf8;--em:#fb923c;
  --font-mono:'IBM Plex Mono',monospace;--font-ui:'Syne',sans-serif;
}
html{font-size:14px}
body{font-family:var(--font-mono);background:var(--bg0);color:var(--text);min-height:100vh;overflow-x:hidden}

body::before{
  content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E");
  background-size:200px 200px;opacity:0.5;
}

/* ── Topbar ── */
#topbar{
  position:sticky;top:0;z-index:200;height:54px;
  background:rgba(5,7,10,0.94);backdrop-filter:blur(20px);
  border-bottom:1px solid var(--line2);
  display:flex;align-items:center;padding:0 24px;gap:0;
}
.logo{display:flex;align-items:center;gap:10px;margin-right:auto}
.logo-mark{
  width:30px;height:30px;border:1.5px solid var(--cyan);border-radius:6px;
  display:flex;align-items:center;justify-content:center;
  box-shadow:0 0 14px rgba(34,211,238,0.22),inset 0 0 10px rgba(34,211,238,0.06);
  position:relative;
}
.logo-mark::before{
  content:'';position:absolute;inset:3px;border:1px solid rgba(34,211,238,0.25);
  border-radius:3px;animation:lp 3s ease-in-out infinite;
}
@keyframes lp{0%,100%{opacity:.3;transform:scale(1)}50%{opacity:1;transform:scale(.88)}}
.logo-mark svg{width:13px;height:13px;fill:var(--cyan)}
.logo-name{font-family:var(--font-ui);font-size:16px;font-weight:700;color:var(--text)}
.logo-ver{font-size:9px;color:var(--text3);background:var(--bg4);border:1px solid var(--line2);padding:1px 7px;border-radius:20px}
.topbar-right{display:flex;align-items:center;gap:18px;font-size:11px;color:var(--text2)}
.tp-item{display:flex;align-items:center;gap:5px}
.ldot{width:5px;height:5px;border-radius:50%;background:var(--green);box-shadow:0 0 5px var(--green);animation:lb 1.4s ease-in-out infinite}
@keyframes lb{0%,100%{opacity:1}50%{opacity:.25}}

/* ── Layout ── */
.main{
  position:relative;z-index:1;max-width:1500px;margin:0 auto;
  padding:24px 24px 48px;
  display:grid;
  grid-template-columns:320px 1fr;
  grid-template-rows:auto auto auto 1fr;
  gap:18px;
}

/* ── Statbar ── */
.statbar{
  grid-column:1/-1;
  display:grid;grid-template-columns:repeat(6,1fr);gap:12px;
}
.sc{
  background:var(--bg2);border:1px solid var(--line);border-radius:10px;
  padding:14px 16px;position:relative;overflow:hidden;
}
.sc::after{
  content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,var(--sc,var(--cyan)),transparent);
  opacity:.5;
}
.sc-label{font-size:9px;letter-spacing:1.5px;text-transform:uppercase;color:var(--text3);margin-bottom:6px}
.sc-val{font-family:var(--font-ui);font-size:24px;font-weight:700;color:var(--sc,var(--cyan));line-height:1}
.sc-sub{font-size:9px;color:var(--text3);margin-top:3px}

/* ── Charts row ── */
.charts-row{
  grid-column:1/-1;
  display:grid;grid-template-columns:1fr 280px;gap:18px;
}

/* ── Panel ── */
.panel{
  background:var(--bg1);border:1px solid var(--line);border-radius:12px;
  overflow:hidden;display:flex;flex-direction:column;
}
.ph{
  padding:12px 18px;border-bottom:1px solid var(--line);
  display:flex;align-items:center;justify-content:space-between;
  background:var(--bg2);flex-shrink:0;
}
.pt{
  font-family:var(--font-ui);font-size:11px;font-weight:600;
  letter-spacing:2px;text-transform:uppercase;color:var(--text2);
  display:flex;align-items:center;gap:7px;
}
.pt-dot{width:5px;height:5px;border-radius:50%;background:var(--cyan);box-shadow:0 0 5px var(--cyan)}

/* ── Activity chart ── */
.activity-wrap{padding:12px 16px;flex:1;min-height:0;position:relative}
canvas#actChart{width:100%!important}

/* ── Donut chart ── */
.donut-wrap{padding:12px 10px;flex:1;display:flex;flex-direction:column;align-items:center;gap:8px}
canvas#donutChart{max-width:160px;max-height:160px}
.donut-legend{width:100%;display:flex;flex-direction:column;gap:4px;padding:0 4px}
.dl-row{display:flex;align-items:center;gap:7px;font-size:10px;color:var(--text2)}
.dl-dot{width:8px;height:8px;border-radius:2px;flex-shrink:0}
.dl-name{flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dl-count{color:var(--text3);font-size:9px}

/* ── Rules panel ── */
.rules-scroll{flex:1;overflow-y:auto;padding:10px;scrollbar-width:thin;scrollbar-color:var(--bg5) transparent}
.rules-scroll::-webkit-scrollbar{width:3px}
.rules-scroll::-webkit-scrollbar-thumb{background:var(--bg5)}
.cat-lbl{font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--text3);padding:8px 6px 3px;font-family:var(--font-ui)}
.rr{
  display:flex;align-items:center;gap:9px;padding:9px 10px;
  border-radius:7px;border:1px solid transparent;cursor:default;
  transition:all .18s;margin-bottom:3px;position:relative;
}
.rr:hover{background:var(--bg3);border-color:var(--line)}
.rr.on{
  background:color-mix(in srgb,var(--rc) 7%,var(--bg2));
  border-color:color-mix(in srgb,var(--rc) 22%,transparent);
}
.rr.on .ri{color:var(--rc);border-color:color-mix(in srgb,var(--rc) 30%,transparent)}
.ri{
  width:32px;height:32px;border-radius:6px;border:1px solid var(--line2);
  display:flex;align-items:center;justify-content:center;
  font-size:14px;color:var(--text3);flex-shrink:0;transition:all .2s;background:var(--bg3);
}
.rb{flex:1;min-width:0}
.rn{font-family:var(--font-ui);font-size:12px;font-weight:600;color:var(--text);display:flex;align-items:center;gap:5px}
.rbadge{font-family:var(--font-mono);font-size:8px;padding:1px 5px;border-radius:3px;background:var(--bg5);color:var(--text3);border:1px solid var(--line2)}
.rd{font-size:9px;color:var(--text3);margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rct{font-size:8px;padding:2px 5px;border-radius:3px;letter-spacing:.8px;font-weight:600;flex-shrink:0}
.chain-INPUT {background:rgba(34,211,238,.08);color:var(--cyan);border:1px solid rgba(34,211,238,.15)}
.chain-OUTPUT{background:rgba(129,140,248,.08);color:var(--indigo);border:1px solid rgba(129,140,248,.15)}
.chain-FORWARD{background:rgba(251,146,60,.08);color:var(--em);border:1px solid rgba(251,146,60,.15)}

/* ── Toggle ── */
.tog{position:relative;width:38px;height:20px;flex-shrink:0;cursor:pointer}
.tog input{position:absolute;opacity:0;width:0;height:0}
.tt{position:absolute;inset:0;background:var(--bg5);border:1px solid var(--line2);border-radius:20px;transition:all .22s}
.th{position:absolute;top:3px;left:3px;width:12px;height:12px;border-radius:50%;background:var(--text3);transition:all .22s cubic-bezier(.4,0,.2,1);box-shadow:0 1px 3px rgba(0,0,0,.5)}
.tog input:checked~.tt{background:color-mix(in srgb,var(--tc) 18%,var(--bg5));border-color:var(--tc)}
.tog input:checked~.th{transform:translateX(18px);background:var(--tc);box-shadow:0 0 7px var(--tc)}
.tog.busy .th{animation:tspin .7s linear infinite}
@keyframes tspin{to{transform:translateX(var(--tx,0)) rotate(360deg)}}

/* ── Actions ── */
.act-row{padding:10px;border-top:1px solid var(--line);display:flex;gap:6px;flex-wrap:wrap;flex-shrink:0}
.btn{
  display:inline-flex;align-items:center;gap:5px;
  padding:6px 12px;border-radius:5px;border:1px solid var(--line2);
  background:var(--bg3);color:var(--text2);
  font-family:var(--font-mono);font-size:10px;font-weight:500;
  cursor:pointer;transition:all .15s;white-space:nowrap;letter-spacing:.3px;
}
.btn:hover{background:var(--bg4);color:var(--text)}
.btn:active{transform:scale(.97)}
.btn-red{color:var(--rose);border-color:rgba(248,113,113,.2)}
.btn-red:hover{background:rgba(248,113,113,.08);border-color:var(--rose)}
.btn-green{color:var(--green);border-color:rgba(74,222,128,.2)}
.btn-green:hover{background:rgba(74,222,128,.08);border-color:var(--green)}
.btn-sky{color:var(--sky);border-color:rgba(56,189,248,.2)}
.btn-sky:hover{background:rgba(56,189,248,.08);border-color:var(--sky)}

/* ── Log panel ── */
.log-panel{grid-column:1/-1}
.log-ph{flex-direction:column;align-items:stretch;gap:8px;padding-bottom:10px}
.log-toolbar{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}
.log-toolbar-right{display:flex;gap:6px;align-items:center}
.log-search{
  flex:1;min-width:180px;
  background:var(--bg0);border:1px solid var(--line2);border-radius:5px;
  padding:5px 10px;font-family:var(--font-mono);font-size:10px;color:var(--text);
  outline:none;transition:border-color .18s;
}
.log-search:focus{border-color:var(--cyan)}
.log-search::placeholder{color:var(--text3)}
.tag-filters{display:flex;gap:4px;flex-wrap:wrap;align-items:center}
.tf{
  font-size:9px;padding:2px 7px;border-radius:3px;border:1px solid var(--line2);
  background:var(--bg3);color:var(--text3);cursor:pointer;font-family:var(--font-mono);
  transition:all .14s;letter-spacing:.3px;
}
.tf:hover{color:var(--text);border-color:var(--line2);background:var(--bg4)}
.tf.on{color:var(--cyan);border-color:rgba(34,211,238,.35);background:rgba(34,211,238,.07)}

/* ── Log table ── */
.log-table-wrap{flex:1;overflow:hidden;display:flex;flex-direction:column}
.log-thead{
  display:grid;grid-template-columns:140px 64px 1fr;
  padding:6px 14px;border-bottom:1px solid var(--line);
  font-size:9px;letter-spacing:1.5px;text-transform:uppercase;color:var(--text3);
  background:var(--bg2);flex-shrink:0;
}
.log-body{
  flex:1;overflow-y:auto;
  scrollbar-width:thin;scrollbar-color:var(--bg5) transparent;
  min-height:320px;max-height:420px;
}
.log-body::-webkit-scrollbar{width:3px}
.log-body::-webkit-scrollbar-thumb{background:var(--bg5);border-radius:2px}

.log-row{
  display:grid;grid-template-columns:140px 64px 1fr;
  padding:5px 14px;border-bottom:1px solid var(--line);
  font-size:10px;line-height:1.5;transition:background .1s;align-items:start;
}
.log-row:hover{background:rgba(255,255,255,.03)}
.log-row:last-child{border-bottom:none}
.lr-ts{color:var(--text3);font-size:9.5px;padding-top:1px}
.lr-tag{
  font-size:8.5px;font-weight:600;padding:1px 6px;border-radius:3px;
  display:inline-flex;align-items:center;justify-content:center;
  width:fit-content;height:fit-content;letter-spacing:.5px;
}
.lr-body{color:var(--text2);word-break:break-all;font-size:10px}
.lr-src{color:#fb923c}.lr-dst{color:#38bdf8}.lr-proto{color:#a78bfa}.lr-iface{color:#4ade80}

/* Tag colors */
.tag-INPUT  {background:rgba(34,211,238,.1);color:#22d3ee}
.tag-OUTPUT {background:rgba(129,140,248,.1);color:#818cf8}
.tag-FORWARD{background:rgba(251,146,60,.1);color:#fb923c}
.tag-HTTP   {background:rgba(74,222,128,.1);color:#4ade80}
.tag-HTTPS  {background:rgba(52,211,153,.1);color:#34d399}
.tag-DNS    {background:rgba(251,191,36,.1);color:#fbbf24}
.tag-SSH    {background:rgba(244,114,182,.1);color:#f472b6}
.tag-ICMP   {background:rgba(167,139,250,.1);color:#a78bfa}
.tag-NEW    {background:rgba(56,189,248,.1);color:#38bdf8}
.tag-DROP   {background:rgba(248,113,113,.1);color:#f87171}

.log-empty{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:48px 0;gap:10px;color:var(--text3);font-size:12px}
.log-empty-ico{font-size:32px;opacity:.15}

/* ── Pagination ── */
.pagination{
  flex-shrink:0;padding:10px 14px;border-top:1px solid var(--line);
  display:flex;align-items:center;gap:8px;background:var(--bg2);
}
.pg-info{font-size:10px;color:var(--text3);margin-right:auto}
.pg-btn{
  width:28px;height:26px;border-radius:4px;border:1px solid var(--line2);
  background:var(--bg3);color:var(--text2);cursor:pointer;
  font-size:11px;display:flex;align-items:center;justify-content:center;
  transition:all .14s;
}
.pg-btn:hover{background:var(--bg4);color:var(--text)}
.pg-btn:disabled{opacity:.3;cursor:not-allowed}
.pg-num{
  min-width:26px;height:26px;border-radius:4px;border:1px solid var(--line2);
  background:var(--bg3);color:var(--text2);cursor:pointer;
  font-size:10px;display:flex;align-items:center;justify-content:center;
  transition:all .14s;font-family:var(--font-mono);
}
.pg-num:hover{background:var(--bg4);color:var(--text)}
.pg-num.cur{background:rgba(34,211,238,.12);color:var(--cyan);border-color:rgba(34,211,238,.3)}
.pg-size{
  background:var(--bg0);border:1px solid var(--line2);border-radius:4px;
  color:var(--text2);font-family:var(--font-mono);font-size:10px;
  padding:3px 6px;outline:none;cursor:pointer;
}
.pg-size:focus{border-color:var(--cyan)}

/* ── Modal ── */
.modal-bg{position:fixed;inset:0;z-index:999;background:rgba(0,0,0,.78);backdrop-filter:blur(6px);display:none;align-items:center;justify-content:center}
.modal-bg.on{display:flex}
.modal{background:var(--bg2);border:1px solid var(--line2);border-radius:13px;padding:30px 34px;max-width:380px;width:90%;box-shadow:0 32px 80px rgba(0,0,0,.7);animation:min .2s ease}
@keyframes min{from{opacity:0;transform:scale(.96) translateY(7px)}to{opacity:1;transform:scale(1) translateY(0)}}
.modal h2{font-family:var(--font-ui);font-size:17px;font-weight:700;color:var(--rose);margin-bottom:8px}
.modal p{color:var(--text2);font-size:11px;line-height:1.8;margin-bottom:22px}
.modal-actions{display:flex;gap:8px;justify-content:flex-end}

/* ── Toasts ── */
.toasts{position:fixed;bottom:18px;right:18px;z-index:9999;display:flex;flex-direction:column;gap:6px;pointer-events:none}
.toast{background:var(--bg3);border:1px solid var(--line2);border-radius:7px;padding:9px 14px;font-size:10px;min-width:220px;display:flex;align-items:center;gap:7px;box-shadow:0 8px 28px rgba(0,0,0,.5);animation:tin .22s ease;pointer-events:all}
.toast.ok{border-color:rgba(74,222,128,.3)}.toast.err{border-color:rgba(248,113,113,.3)}.toast.inf{border-color:rgba(34,211,238,.3)}
.toast.out{animation:tout .22s ease forwards}
@keyframes tin{from{opacity:0;transform:translateX(14px)}to{opacity:1;transform:translateX(0)}}
@keyframes tout{from{opacity:1}to{opacity:0;transform:translateX(14px)}}

.footer{grid-column:1/-1;display:flex;align-items:center;justify-content:space-between;padding-top:12px;border-top:1px solid var(--line);font-size:10px;color:var(--text3)}

@media(max-width:1100px){.main{grid-template-columns:1fr}.charts-row{grid-template-columns:1fr}.statbar{grid-template-columns:repeat(3,1fr)}}
@media(max-width:600px){.statbar{grid-template-columns:repeat(2,1fr)}.log-thead,.log-row{grid-template-columns:100px 56px 1fr}}
</style>
</head>
<body>

<nav id="topbar">
  <div class="logo">
    <div class="logo-mark">
      <svg viewBox="0 0 16 16"><path d="M8 1L2 4v4c0 3.3 2.5 6.4 6 7 3.5-.6 6-3.7 6-7V4L8 1z"/></svg>
    </div>
    <span class="logo-name">NetGuard</span>
    <span class="logo-ver">v__VER__</span>
  </div>
  <div class="topbar-right">
    <div class="tp-item"><div class="ldot"></div><span id="tp-active">— active</span></div>
    <div class="tp-item" style="color:var(--text3)">|</div>
    <div class="tp-item" id="tp-logsize">—</div>
    <div class="tp-item" style="color:var(--text3)">|</div>
    <div class="tp-item" id="tp-time">—</div>
  </div>
</nav>

<div class="main">

  <!-- Stats -->
  <div class="statbar">
    <div class="sc" style="--sc:var(--cyan)">
      <div class="sc-label">Active Rules</div>
      <div class="sc-val" id="s-active">0</div>
      <div class="sc-sub">of __TOTAL__ profiles</div>
    </div>
    <div class="sc" style="--sc:var(--green)">
      <div class="sc-label">INPUT Rules</div>
      <div class="sc-val" id="s-in">0</div>
      <div class="sc-sub">chain LOG count</div>
    </div>
    <div class="sc" style="--sc:var(--indigo)">
      <div class="sc-label">OUTPUT Rules</div>
      <div class="sc-val" id="s-out">0</div>
      <div class="sc-sub">chain LOG count</div>
    </div>
    <div class="sc" style="--sc:var(--em)">
      <div class="sc-label">FORWARD Rules</div>
      <div class="sc-val" id="s-fwd">0</div>
      <div class="sc-sub">chain LOG count</div>
    </div>
    <div class="sc" style="--sc:var(--amber)">
      <div class="sc-label">Total Packets</div>
      <div class="sc-val" id="s-pkts">0</div>
      <div class="sc-sub">logged this session</div>
    </div>
    <div class="sc" style="--sc:var(--violet)">
      <div class="sc-label">Log File Size</div>
      <div class="sc-val" id="s-size">0B</div>
      <div class="sc-sub">/var/log/iptables.log</div>
    </div>
  </div>

  <!-- Charts row -->
  <div class="charts-row">
    <!-- Activity chart -->
    <div class="panel" style="height:200px">
      <div class="ph">
        <div class="pt"><div class="pt-dot"></div>Packet Activity Timeline</div>
        <span style="font-size:10px;color:var(--text3)" id="act-info">—</span>
      </div>
      <div class="activity-wrap">
        <canvas id="actChart"></canvas>
      </div>
    </div>
    <!-- Donut chart -->
    <div class="panel" style="height:200px">
      <div class="ph">
        <div class="pt"><div class="pt-dot"></div>By Rule</div>
        <span style="font-size:10px;color:var(--text3)" id="donut-total">—</span>
      </div>
      <div class="donut-wrap">
        <canvas id="donutChart"></canvas>
        <div class="donut-legend" id="donut-legend"></div>
      </div>
    </div>
  </div>

  <!-- Left: Rules -->
  <div class="panel" style="grid-row:3/5">
    <div class="ph">
      <div class="pt"><div class="pt-dot"></div>Logging Rules</div>
      <span style="font-size:10px;color:var(--text3)">toggle to activate</span>
    </div>
    <div class="rules-scroll" id="rules-list"></div>
    <div class="act-row">
      <button class="btn btn-red"   onclick="confirmClear()">⊗ Clear All</button>
      <button class="btn btn-green" onclick="enableAll()">↑ Enable All</button>
      <button class="btn btn-sky"   onclick="saveRules()">⬡ Persist</button>
      <button class="btn"           onclick="doRefresh()">↻ Refresh</button>
    </div>
  </div>

  <!-- Right: Log panel -->
  <div class="panel log-panel">
    <div class="ph log-ph">
      <div class="log-toolbar">
        <div class="pt"><div class="pt-dot"></div>Live Log Stream</div>
        <div class="log-toolbar-right">
          <label style="display:flex;align-items:center;gap:5px;font-size:10px;color:var(--text2);cursor:pointer">
            <input type="checkbox" id="autoscroll" checked style="accent-color:var(--cyan)"> Auto-scroll
          </label>
          <button class="btn btn-red" style="padding:4px 9px;font-size:9px" onclick="clearLogFile()">Clear Log</button>
        </div>
      </div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input class="log-search" id="log-search" placeholder="Search IPs, ports, protocols..." oninput="applyFilter()">
        <div class="tag-filters" id="tag-filters"></div>
      </div>
    </div>
    <div class="log-table-wrap">
      <div class="log-thead">
        <span>Timestamp</span><span>Rule</span><span>Packet Info</span>
      </div>
      <div class="log-body" id="log-body">
        <div class="log-empty"><div class="log-empty-ico">◎</div><span>Waiting for packets…</span></div>
      </div>
    </div>
    <div class="pagination">
      <span class="pg-info" id="pg-info">—</span>
      <select class="pg-size" id="pg-size" onchange="changePageSize()">
        <option value="25">25/page</option>
        <option value="50" selected>50/page</option>
        <option value="100">100/page</option>
        <option value="200">200/page</option>
      </select>
      <button class="pg-btn" id="pg-prev" onclick="goPage(curPage-1)">‹</button>
      <div id="pg-nums" style="display:flex;gap:4px"></div>
      <button class="pg-btn" id="pg-next" onclick="goPage(curPage+1)">›</button>
    </div>
  </div>

  <div class="footer">
    <span>NetGuard IPTables Manager — Production Edition</span>
    <span id="footer-ts">—</span>
  </div>
</div>

<!-- Modal -->
<div class="modal-bg" id="modal">
  <div class="modal">
    <h2>⊗ Clear All Rules</h2>
    <p>This removes all NetGuard LOG rules from INPUT, OUTPUT, and FORWARD chains immediately.<br><br>Active traffic is unaffected. The log file is preserved.</p>
    <div class="modal-actions">
      <button class="btn" onclick="closeModal()">Cancel</button>
      <button class="btn btn-red" onclick="doClear()">Confirm Clear</button>
    </div>
  </div>
</div>

<div class="toasts" id="toasts"></div>

<script>
// ── Config ────────────────────────────────────────────────────────────────────
const P = __PROFILES__;
const TAG_COLORS = __TAG_COLORS__;
let allLines = [], filtered = [], curPage = 1, pageSize = 50;
let activeTag = null;
let actChart = null, donutChart = null;
let statusCache = {};

// ── Init charts ───────────────────────────────────────────────────────────────
function initCharts() {
  // Activity line chart
  const actCtx = document.getElementById('actChart').getContext('2d');
  actChart = new Chart(actCtx, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Packets',
        data: [],
        backgroundColor: 'rgba(34,211,238,0.18)',
        borderColor: 'rgba(34,211,238,0.7)',
        borderWidth: 1,
        borderRadius: 2,
        borderSkipped: false,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: { duration: 400 },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0c1018',
          borderColor: 'rgba(255,255,255,0.1)',
          borderWidth: 1,
          titleColor: '#7a8899',
          bodyColor: '#22d3ee',
          titleFont: { family: "'IBM Plex Mono'" },
          bodyFont: { family: "'IBM Plex Mono'", size: 11 },
          callbacks: { title: (i) => i[0].label, label: (i) => ` ${i.raw} packets` }
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(255,255,255,0.04)', drawBorder: false },
          ticks: { color: '#3d4d60', font: { family: "'IBM Plex Mono'", size: 9 }, maxTicksLimit: 10, maxRotation: 0 },
          border: { display: false }
        },
        y: {
          grid: { color: 'rgba(255,255,255,0.04)', drawBorder: false },
          ticks: { color: '#3d4d60', font: { family: "'IBM Plex Mono'", size: 9 }, precision: 0 },
          border: { display: false }, beginAtZero: true
        }
      }
    }
  });

  // Donut chart
  const donutCtx = document.getElementById('donutChart').getContext('2d');
  donutChart = new Chart(donutCtx, {
    type: 'doughnut',
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderColor: '#080c12', borderWidth: 2, hoverOffset: 4 }] },
    options: {
      responsive: true, maintainAspectRatio: true,
      cutout: '68%',
      animation: { duration: 500 },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0c1018',
          borderColor: 'rgba(255,255,255,0.1)',
          borderWidth: 1,
          bodyColor: '#e8edf5',
          bodyFont: { family: "'IBM Plex Mono'", size: 11 },
          callbacks: {
            label: (i) => ` ${i.label}: ${i.raw} pkts (${Math.round(i.raw/i.dataset.data.reduce((a,b)=>a+b,0)*100)}%)`
          }
        }
      }
    }
  });
}

// ── Update activity chart from real data ──────────────────────────────────────
function updateActivityChart(buckets) {
  if (!actChart || !buckets.length) return;
  actChart.data.labels   = buckets.map(b => b.label);
  actChart.data.datasets[0].data = buckets.map(b => b.count);

  // Color bars by intensity
  const max = Math.max(...buckets.map(b=>b.count), 1);
  actChart.data.datasets[0].backgroundColor = buckets.map(b => {
    const a = 0.1 + (b.count/max)*0.5;
    return `rgba(34,211,238,${a})`;
  });
  actChart.update('none');

  const total = buckets.reduce((s,b)=>s+b.count,0);
  const peak  = Math.max(...buckets.map(b=>b.count));
  document.getElementById('act-info').textContent = `${total} total · peak ${peak}`;
}

// ── Update donut chart ────────────────────────────────────────────────────────
function updateDonutChart(byTag) {
  if (!donutChart) return;
  const entries = Object.entries(byTag).sort((a,b)=>b[1]-a[1]);
  if (!entries.length) return;

  const labels = entries.map(([t])=>t);
  const data   = entries.map(([,c])=>c);
  const colors = entries.map(([t])=> TAG_COLORS[t] || '#7a8899');
  const total  = data.reduce((a,b)=>a+b,0);

  donutChart.data.labels = labels;
  donutChart.data.datasets[0].data = data;
  donutChart.data.datasets[0].backgroundColor = colors;
  donutChart.update();

  document.getElementById('donut-total').textContent = `${total} total`;
  document.getElementById('donut-legend').innerHTML = entries.map(([tag,cnt])=>`
    <div class="dl-row">
      <div class="dl-dot" style="background:${TAG_COLORS[tag]||'#7a8899'}"></div>
      <span class="dl-name">${tag}</span>
      <span class="dl-count">${cnt}</span>
    </div>`).join('');
}

// ── Render rules list ─────────────────────────────────────────────────────────
function renderRules(active) {
  const list = document.getElementById('rules-list');
  const cats = {};
  for (const [id,p] of Object.entries(P)) {
    if (!cats[p.category]) cats[p.category]=[];
    cats[p.category].push([id,p]);
  }
  let html = '';
  for (const [cat,rules] of Object.entries(cats)) {
    html += `<div class="cat-lbl">${cat}</div>`;
    for (const [id,p] of rules) {
      const on = active[id]||false;
      html += `<div class="rr ${on?'on':''}" id="rr-${id}" style="--rc:${p.color}">
        <div class="ri">${p.icon}</div>
        <div class="rb">
          <div class="rn">${p.name}<span class="rbadge">${p.short}</span></div>
          <div class="rd">${p.description}</div>
        </div>
        <span class="rct chain-${p.chain}">${p.chain}</span>
        <label class="tog" style="--tc:${p.color}" id="tog-${id}">
          <input type="checkbox" id="chk-${id}" ${on?'checked':''} onchange="toggle('${id}',this.checked)">
          <div class="tt"></div><div class="th"></div>
        </label>
      </div>`;
    }
  }
  list.innerHTML = html;
}

// ── Toggle rule ───────────────────────────────────────────────────────────────
async function toggle(id, enable) {
  const chk=document.getElementById('chk-'+id);
  const tog=document.getElementById('tog-'+id);
  const row=document.getElementById('rr-'+id);
  chk.disabled=true; tog.classList.add('busy');
  try {
    const r = await fetch('/api/toggle/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enable})});
    const d = await r.json();
    if (d.success) {
      chk.checked=d.active; row.classList.toggle('on',d.active);
      toast(d.active?`${P[id].name} enabled`:`${P[id].name} disabled`, d.active?'ok':'inf');
    } else { chk.checked=!enable; toast('Error: '+d.message,'err'); }
  } catch(e) { chk.checked=!enable; toast('Network error','err'); }
  chk.disabled=false; tog.classList.remove('busy');
  setTimeout(doRefresh,400);
}

// ── Status refresh ────────────────────────────────────────────────────────────
async function doRefresh() {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    statusCache = d;
    const cnt = d.rule_counts||{};
    const activeN = Object.values(d.rules).filter(Boolean).length;

    for (const [id,on] of Object.entries(d.rules)) {
      const chk=document.getElementById('chk-'+id);
      const row=document.getElementById('rr-'+id);
      if (chk&&!chk.disabled) chk.checked=on;
      if (row) row.classList.toggle('on',on);
    }

    document.getElementById('s-active').textContent = activeN;
    document.getElementById('s-in').textContent     = cnt.INPUT||0;
    document.getElementById('s-out').textContent    = cnt.OUTPUT||0;
    document.getElementById('s-fwd').textContent    = cnt.FORWARD||0;
    document.getElementById('s-size').textContent   = fmtBytes(d.log_size||0);
    document.getElementById('tp-active').textContent= activeN+' active';
    document.getElementById('tp-logsize').textContent= fmtBytes(d.log_size||0);
  } catch(e) {}
}

// ── Load logs ─────────────────────────────────────────────────────────────────
async function loadLogs() {
  try {
    const r = await fetch('/api/logs?n=2000');
    const d = await r.json();
    allLines = d.lines||[];
    document.getElementById('s-pkts').textContent = allLines.length;

    // Charts
    if (d.buckets) updateActivityChart(d.buckets);
    if (d.by_tag)  updateDonutChart(d.by_tag);

    buildTagFilters();
    applyFilter();
  } catch(e) {}
}

// ── Tag filter buttons ────────────────────────────────────────────────────────
function buildTagFilters() {
  const tags = [...new Set(allLines.map(l=>{ const m=l.match(/\[IPTABLES (\w+)\]/); return m?m[1]:null; }).filter(Boolean))];
  const wrap = document.getElementById('tag-filters');
  wrap.innerHTML = tags.map(t=>`
    <button class="tf ${activeTag===t?'on':''}" data-tag="${t}" onclick="setTag('${t}')">${t}</button>
  `).join('');
}

function setTag(tag) {
  activeTag = activeTag===tag ? null : tag;
  document.querySelectorAll('.tf').forEach(b=>b.classList.toggle('on', b.dataset.tag===activeTag));
  curPage=1; applyFilter();
}

// ── Filter + paginate ─────────────────────────────────────────────────────────
function applyFilter() {
  const q = document.getElementById('log-search').value.toLowerCase();
  filtered = allLines.filter(l=>{
    if (activeTag && !l.includes('[IPTABLES '+activeTag+']')) return false;
    if (q && !l.toLowerCase().includes(q)) return false;
    return true;
  });
  curPage = Math.min(curPage, Math.ceil(filtered.length/pageSize)||1);
  renderLogs();
  renderPagination();
}

function renderLogs() {
  const body = document.getElementById('log-body');
  const as   = document.getElementById('autoscroll').checked;
  if (!filtered.length) {
    body.innerHTML=`<div class="log-empty"><div class="log-empty-ico">◎</div><span>${allLines.length?'No matches for current filter':'Waiting for packets…'}</span></div>`;
    return;
  }
  const start = (curPage-1)*pageSize;
  const page  = filtered.slice(start, start+pageSize);
  body.innerHTML = page.map(fmtRow).join('');
  if (as) body.scrollTop = body.scrollHeight;
}

function fmtRow(line) {
  const m = line.match(/^(\S+)\s+\S+\s+kernel:\s+\[IPTABLES (\w+)\]\s+(.+)$/);
  if (!m) return `<div class="log-row"><span class="lr-ts">—</span><span></span><span class="lr-body" style="color:var(--text3)">${esc(line)}</span></div>`;
  let [,ts,tag,body]=m;
  ts = ts.replace(/T/,' ').replace(/\.\d+.*/,'').substring(5);
  body = body
    .replace(/IN=(\S+)/g, 'IN=<span class="lr-iface">$1</span>')
    .replace(/SRC=([\d.:a-f]+)/g,'SRC=<span class="lr-src">$1</span>')
    .replace(/DST=([\d.:a-f]+)/g,'DST=<span class="lr-dst">$1</span>')
    .replace(/PROTO=(\w+)/g,'PROTO=<span class="lr-proto">$1</span>');
  return `<div class="log-row">
    <span class="lr-ts">${esc(ts)}</span>
    <span class="lr-tag tag-${tag}">${tag}</span>
    <span class="lr-body">${body}</span>
  </div>`;
}

// ── Pagination ────────────────────────────────────────────────────────────────
function renderPagination() {
  const total = filtered.length;
  const pages = Math.ceil(total/pageSize)||1;
  const start = (curPage-1)*pageSize+1;
  const end   = Math.min(curPage*pageSize, total);

  document.getElementById('pg-info').textContent = total ? `${start}–${end} of ${total} entries` : 'No entries';
  document.getElementById('pg-prev').disabled = curPage<=1;
  document.getElementById('pg-next').disabled = curPage>=pages;

  // Page number buttons (show max 7)
  const nums = document.getElementById('pg-nums');
  let btns = [], lo=Math.max(1,curPage-3), hi=Math.min(pages,curPage+3);
  if (lo>1)     btns.push('<span style="color:var(--text3);font-size:10px;padding:0 2px">…</span>');
  for (let i=lo;i<=hi;i++) btns.push(`<button class="pg-num ${i===curPage?'cur':''}" onclick="goPage(${i})">${i}</button>`);
  if (hi<pages) btns.push('<span style="color:var(--text3);font-size:10px;padding:0 2px">…</span>');
  nums.innerHTML = btns.join('');
}

function goPage(n) {
  const pages = Math.ceil(filtered.length/pageSize)||1;
  curPage = Math.max(1, Math.min(n, pages));
  renderLogs(); renderPagination();
  document.getElementById('log-body').scrollTop=0;
}

function changePageSize() {
  pageSize = parseInt(document.getElementById('pg-size').value);
  curPage=1; renderLogs(); renderPagination();
}

// ── Actions ───────────────────────────────────────────────────────────────────
function confirmClear() { document.getElementById('modal').classList.add('on'); }
function closeModal()   { document.getElementById('modal').classList.remove('on'); }

async function doClear() {
  closeModal();
  const d = await (await fetch('/api/clear-all',{method:'POST'})).json();
  toast(d.message,'ok');
  await doRefresh();
  renderRules(Object.fromEntries(Object.keys(P).map(k=>[k,false])));
}

async function enableAll() {
  for (const id of Object.keys(P)) {
    const chk = document.getElementById('chk-'+id);
    if (chk && !chk.checked) await toggle(id,true);
  }
}

async function saveRules() {
  const d = await (await fetch('/api/save-rules',{method:'POST'})).json();
  toast(d.message, d.success?'ok':'err');
}

async function clearLogFile() {
  if (!confirm('Clear /var/log/iptables.log?')) return;
  const d = await (await fetch('/api/clear-log',{method:'POST'})).json();
  toast(d.message, d.success?'ok':'err');
  if (d.success){ allLines=[]; filtered=[]; renderLogs(); renderPagination(); }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmtBytes(b){ if(b<1024)return b+'B'; if(b<1048576)return(b/1024).toFixed(1)+'KB'; return(b/1048576).toFixed(1)+'MB'; }
function esc(s){ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function toast(msg,type='inf'){
  const ico={ok:'✓',err:'✕',inf:'◎'}[type]||'◎';
  const el=document.createElement('div');
  el.className='toast '+type;
  el.innerHTML=`<span>${ico}</span><span>${msg}</span>`;
  document.getElementById('toasts').appendChild(el);
  setTimeout(()=>{el.classList.add('out');setTimeout(()=>el.remove(),240);},3000);
}

function tick(){
  const now=new Date();
  document.getElementById('tp-time').textContent=now.toLocaleTimeString('en-GB',{hour12:false});
  document.getElementById('footer-ts').textContent='Updated '+now.toLocaleString('en-GB');
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────
async function init(){
  initCharts();
  renderRules(Object.fromEntries(Object.keys(P).map(k=>[k,false])));
  await doRefresh();
  if(statusCache.rules) renderRules(statusCache.rules);
  await loadLogs();
  tick();
}

init();
setInterval(async()=>{ await doRefresh(); await loadLogs(); tick(); }, 5000);
</script>
</body>
</html>
"""

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    page = (HTML
        .replace("__PROFILES__",  json.dumps(RULE_PROFILES))
        .replace("__TAG_COLORS__", json.dumps(TAG_COLOR))
        .replace("__VER__",        VERSION)
        .replace("__TOTAL__",      str(len(RULE_PROFILES))))
    return Response(page, mimetype="text/html")

@app.route("/api/status")
def api_status():
    state = load_state()
    verified = {}
    for rid, p in RULE_PROFILES.items():
        actual = rule_exists(p)
        verified[rid] = actual
        if actual != state.get(rid, False):
            state[rid] = actual
    save_state(state)
    return jsonify({
        "rules":       verified,
        "rule_counts": chain_counts(),
        "log_exists":  os.path.exists(LOG_FILE),
        "log_size":    os.path.getsize(LOG_FILE) if os.path.exists(LOG_FILE) else 0,
    })

@app.route("/api/toggle/<rid>", methods=["POST"])
def api_toggle(rid):
    if rid not in RULE_PROFILES:
        return jsonify({"success": False, "message": "Unknown rule"}), 404
    p      = RULE_PROFILES[rid]
    data   = request.get_json() or {}
    enable = data.get("enable", True)
    if enable:
        if rule_exists(p):
            return jsonify({"success": True, "active": True, "message": "Already active"})
        ok, msg = add_rule(p)
    else:
        if not rule_exists(p):
            return jsonify({"success": True, "active": False, "message": "Already inactive"})
        ok, msg = remove_rule(p)
    if ok:
        state = load_state()
        state[rid] = enable
        save_state(state)
    return jsonify({
        "success": ok,
        "active":  enable if ok else not enable,
        "message": ("Enabled" if enable else "Disabled") if ok else msg,
    })

@app.route("/api/clear-all", methods=["POST"])
def api_clear_all():
    n = clear_all_rules()
    save_state({k: False for k in RULE_PROFILES})
    return jsonify({"success": True, "removed": n, "message": f"Cleared {n} LOG rules"})

@app.route("/api/logs")
def api_logs():
    n     = int(request.args.get("n", 2000))
    lines = get_all_logs(n)
    tc    = tag_counts(lines)
    bkts  = activity_buckets(lines, buckets=40)
    return jsonify({"lines": lines, "count": len(lines), "by_tag": tc, "buckets": bkts})

@app.route("/api/clear-log", methods=["POST"])
def api_clear_log():
    try:
        open(LOG_FILE, 'w').close()
        return jsonify({"success": True, "message": "Log file cleared"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/api/save-rules", methods=["POST"])
def api_save_rules():
    try:
        os.makedirs("/etc/iptables", exist_ok=True)
        r = subprocess.run(["iptables-save"], capture_output=True, text=True)
        with open("/etc/iptables/rules.v4", "w") as f:
            f.write(r.stdout)
        return jsonify({"success": True, "message": "Rules persisted to /etc/iptables/rules.v4"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("⚠  Run as root: sudo python3 app.py")
    print(f"🛡  NetGuard v{VERSION} — http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)