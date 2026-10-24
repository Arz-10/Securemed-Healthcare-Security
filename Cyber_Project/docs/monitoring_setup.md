# SecureMed — Security Monitoring, NIDS, and SIEM Integration Guide

This document details the monitoring architecture, environment status, and integration plans for incorporating external security tools (Nmap, Wireshark, Suricata, OpenVAS, and Wazuh) with SecureMed.

---

## 1. Environment Status & Tool Availability

An automated environment audit was performed on the active host system (`Windows 10/11`, PowerShell):

| Security Tool | Expected Binary | Current Host Status | Integration Status |
| :--- | :--- | :---: | :--- |
| **Nmap** | `nmap.exe` | **Not Installed** | Configuration & scan templates ready below |
| **Wireshark / TShark** | `tshark.exe`, `wireshark.exe` | **Not Installed** | Packet capture filters & demo script ready below |
| **Suricata** | `suricata.exe` | **Not Installed** | Custom HTTP NIDS rules ready below |
| **OpenVAS / Greenbone** | Web/CLI Scanner | **Not Installed** | Authenticated/Unauthenticated scan plan below |
| **Wazuh SIEM** | `wazuh-agent.exe` | **Not Installed** | Custom decoder, rules & log forwarder ready below |

> **Compliance Note:** In accordance with project integrity standards, scan outputs are not fabricated. Ready-to-execute configurations and rules are documented below for environments where these tools are installed.

---

## 2. Nmap (Network Discovery & Port Auditing)

### Target Scope:
Authorized local testing only against `127.0.0.1` (development host).

### Command Reference:
```powershell
# 1. Fast service & version discovery on SecureMed port 5000
nmap -sV -p 5000 127.0.0.1 -oN nmap_securemed_service.txt

# 2. Comprehensive HTTP security header and method scan
nmap -p 5000 --script http-headers,http-methods,http-title 127.0.0.1 -oN nmap_http_enum.txt

# 3. Non-destructive vulnerability script audit
nmap -p 5000 --script vuln 127.0.0.1 -oN nmap_vuln_scan.txt
```

### Expected Output Summary:
- Port 5000/TCP open (`Werkzeug httpd` / `Python`).
- Supported HTTP methods: `GET`, `POST`, `HEAD`, `OPTIONS`.
- No anonymous directory listing permitted.

---

## 3. Wireshark / TShark (Packet Inspection & Demonstration)

Used to demonstrate cleartext HTTP risks vs. HTTPS encryption during controlled local presentations.

### Setup Instructions:
1. Download Wireshark from `https://www.wireshark.org/download.html`.
2. Select loopback adapter (`Npcap Loopback Adapter`) for monitoring `127.0.0.1`.

### Key Display Filters:
```wireshark
# Capture HTTP traffic directed at SecureMed port 5000
tcp.port == 5000 && http

# Isolate state-changing POST requests (logins, bookings, record submissions)
http.request.method == "POST"

# Inspect CSRF and session cookies in transit
http.cookie contains "session"
```

### Demonstration Takeaway:
Shows why `SESSION_COOKIE_SECURE = True` and TLS termination (HTTPS) are required in production environments to protect cleartext session cookies and medical record payloads in transit.

---

## 4. Suricata (Network Intrusion Detection System)

Suricata can be deployed on the network gateway or host interface to detect exploit payloads targeting SecureMed endpoints.

### Custom Rule Definitions (`securemed_rules.rules`):

```suricata
# 1. Detect SQL Injection attempt in HTTP POST parameters
alert http any any -> any 5000 (msg:"SECUREMED - SQL Injection Attempt Detected"; flow:to_server,established; content:"POST"; http_method; content:"%27+OR+"; http_client_body; nocase; classtype:web-application-attack; sid:1000001; rev:1;)

# 2. Detect Path Traversal attempt in file upload or download
alert http any any -> any 5000 (msg:"SECUREMED - Path Traversal Attempt in URI"; flow:to_server,established; content:"..%2F"; http_uri; classtype:attempted-recon; sid:1000002; rev:1;)

# 3. Detect Cross-Site Scripting (XSS) script tag injection
alert http any any -> any 5000 (msg:"SECUREMED - Reflected/Stored XSS Script Tag Detected"; flow:to_server,established; content:"%3Cscript%3E"; http_client_body; nocase; classtype:web-application-attack; sid:1000003; rev:1;)
```

---

## 5. OpenVAS / Greenbone (Vulnerability Assessment)

### Setup & Scan Profile:
1. Deploy OpenVAS container or Linux scanner appliance on authorized test subnet.
2. Define Target: `http://192.168.x.x:5000` (or local host gateway).
3. Configure **Web Application Scan** policy:
   - Check HTTP security headers (`X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`).
   - Check Cookie flags (`HttpOnly`, `SameSite`, `Secure`).
   - Audit parameter fuzzing on `/login` and `/reports/download/<id>`.
4. Scan exclusion: Exclude destructive denial-of-service tests (`NVT: DoS`).

---

## 6. Wazuh (Host-Based Security & SIEM Event Forwarding)

SecureMed's internal `audit_logs` database can be forwarded into Wazuh for real-time alerting on repeated failed logins, account deactivations, and unauthorized access attempts.

### Log Export Architecture:
A background forwarder queries new entries from `securemed_db.audit_logs` every 10 seconds and writes them as JSON to `C:\ProgramData\SecureMed\logs\audit_events.json`.

### Sample Wazuh Custom Decoder (`/var/ossec/etc/decoders/local_decoder.xml`):
```xml
<decoder name="securemed-json">
  <prematch>^{"source":"securemed"</prematch>
</decoder>

<decoder name="securemed-json-fields">
  <parent>securemed-json</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

### Sample Wazuh Alert Rules (`/var/ossec/etc/rules/local_rules.xml`):
```xml
<group name="securemed,hipaa,">
  <!-- Base rule for any SecureMed audit event -->
  <rule id="100500" level="3">
    <decoded_as>securemed-json</decoded_as>
    <description>SecureMed application security event</description>
  </rule>

  <!-- Alert on Unauthorized Access Attempts -->
  <rule id="100501" level="8">
    <if_sid>100500</if_sid>
    <field name="event_type">UNAUTHORIZED_ACCESS</field>
    <description>SecureMed: Unauthorized access attempt detected (IDOR or Privilege Mismatch)</description>
    <mitre>
      <id>T1078</id>
    </mitre>
  </rule>

  <!-- Alert on Brute-force Bursts: 5 Failed Logins within 60 seconds -->
  <rule id="100502" level="10" frequency="5" timeframe="60">
    <if_matched_sid>100500</if_matched_sid>
    <field name="event_type">LOGIN_FAILED</field>
    <same_source_ip />
    <description>SecureMed: Potential brute-force attack detected from source IP</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```
