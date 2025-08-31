<h1 = align=center>𝚆𝙸𝚁𝙴𝚂𝙷𝙰𝚁𝙺 𝙿𝙰𝙲𝙺𝙴𝚃 𝙰𝙽𝙰𝙻𝚈𝚂𝙸𝚂</h1>
<p = align=center>

</p>
## 🛠️ TECHNOLOGY & PLATFORMS UTILIZED

- [`Wireshark:`](https://www.wireshark.org/download.html)</br>
  Core tool used for capturing and analyzing network traffic across various protocols.

- [`VirtualBox:`](https://www.virtualbox.org/)</br>
  Hosted multiple isolated virtual machines for safely simulating real-world networking environments and security attacks.

- [`Ubuntu 22.04:`](https://releases.ubuntu.com/jammy/)</br>
  Deployed on two separate virtual machines—one configured as the attacker/client and the other as the server/analyzer.

- [`Suricata 7.0.11:`](https://suricata.io/2025/07/08/suricata-7-0-11-released/)</br>
  Suricata is a network security tool that inspects traffic in real time to identify and stop attacks..
---

## OBJECTIVE

This project involved the design and execution of a comprehensive series of network security simulations using `Wireshark` in a controlled virtual lab environment. Leveraging `VirtualBox` and multiple `Linux` virtual machines, I captured and analyzed network traffic across a variety of protocols to simulate both normal and malicious behavior. Key scenarios included `TCP handshakes`, `SYN scans`, `DNS tunneling`, `ARP spoofing`, `credential leakage` via HTTP and FTP, `Telnet/SSH` sessions, `TLS/SSL handshakes`, and `DoS` indicators. Each simulation was crafted to mirror real-world attack patterns or defensive monitoring tasks, providing deep insights into packet-level behavior, protocol vulnerabilities, and network-based threat detection techniques. This project demonstrated hands-on proficiency in packet analysis, threat simulation, and network forensic workflows.

---

## 📜 TABLE OF CONTENTS

- [`Packet Analysis with Suricata`](#packet-analysis-with-suricata)
- [`TCP 3-WAY HANDSHAKE`](#tcp-3-way-handshake)
- [`DNS TUNNELING`](#dns-tunneling)
- [`ARP SPOOFING & MAN-IN-THE-MIDDLE ATTACK`](#arp-spoofing--man-in-the-middle-attack)
- [`CREDENTIAL LEAKAGE`](#credential-leakage)
- [`DOS ATTACK SIMULATION`](#dos-attack-simulation)

---


## DETECTING AND ANALYSING TRAFFIC WITH SURICATA

Step 1. Prepare the Environment, using ` Kali Linux `as the Operating System. Setup Kali Linux on a Virtual Machine using virtualBox.

Step2. Install Suricata on the Kali Linux Operating System. Open the terminal and update the package list:
```bash
sudo apt update
```
To install Suricata on Kali Linux

```bash
sudo apt inastall suricata
```

Step 3. Update the Suricata rule set:
```bash
sudo suricata-update
```

Step4: Next, create a custom rule
Open the local.rule file in nano editor
```bash
sudo nano
/var/lib/suricata//rules/local.rules
```
After adding custom rules, Add the rule to detect ICMP ping requests:

```bash
alert icmp any any -> any any (msg:"ICMP Ping Dectected"; itype:8; sid:1000001; rev:1;)
```

Step 5: Update Suricata Configuration
Open the suricata configuration file:
```bash
sudo nano
/etc/suricata/suricata.yaml
```

Set the `default-rule-path` and include `local.rules` in the `rule-files` section.

Step 6: Apply the changes by restarting Suricata:
```bash
sudo systemctl restart suricata
```

Step 7: Run suricata to verify rules are loaded:
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -v
```

Step 8:Generate traffic to trigger the rule:
```bash
ping -c 4 8.8.8.8
```

Step 9:Verify the detection in the Suricata logs
```bash
sudo cat /var/log/suricata/eve.json | grep "ICMP Ping Detected"
```

Step 10: Using Wireshark tocapture and filter ICMP traffic
