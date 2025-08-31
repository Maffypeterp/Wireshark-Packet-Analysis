<h1 = align=center>𝚆𝙸𝚁𝙴𝚂𝙷𝙰𝚁𝙺 𝙿𝙰𝙲𝙺𝙴𝚃 𝙰𝙽𝙰𝙻𝚈𝚂𝙸𝚂</h1>
<p = align=center>

<img width="512" height="388" alt="Image" src="https://github.com/user-attachments/assets/3990ab56-6316-43d6-a4bd-722d40af3fa3" />

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

<img width="597" height="303" alt="Image" src="https://github.com/user-attachments/assets/74c3c280-3d46-4d89-907f-75ed57c23cb6" />

---
Step 1. Prepare the Environment, using ` Kali Linux `as the Operating System. Setup Kali Linux on a Virtual Machine using virtualBox.

<img width="640" height="562" alt="Image" src="https://github.com/user-attachments/assets/31055b3a-bd46-4beb-9005-e10b2abb4b86" />

---

Step2. Install Suricata on the Kali Linux Operating System. Open the terminal and update the package list:
```bash
sudo apt update
```
To install and configure `Suricata `on `Kali Linux`, to act as an Intrusion Detection System

```bash
sudo apt install suricata
```
<img width="606" height="230" alt="Image" src="https://github.com/user-attachments/assets/f0152a07-e95e-4ea5-9682-e66d987cf703" />

---

Step 3. Update the Suricata rule set:
```bash
sudo suricata-update
```
<img width="797" height="562" alt="Image" src="https://github.com/user-attachments/assets/c4c4aca3-0a36-4927-9bea-db6aeb08cbf4" />

---

Step4: Next, create a custom rule
Open the local.rule file in GNU nano editor

```bash
sudo nano
/var/lib/suricata//rules/local.rules
```

<img width="545" height="67" alt="Image" src="https://github.com/user-attachments/assets/fd208556-88ac-4e13-8bca-352a38231d86" />

After adding custom rules, Add the rule to detect ICMP ping requests:

```bash
alert icmp any any -> any any (msg:"ICMP Ping Dectected"; itype:8; sid:1000001; rev:1;)
```

<img width="800" height="597" alt="Image" src="https://github.com/user-attachments/assets/51329592-92f1-423a-b8ec-482ce1454581" />

Generate an alert on ICMP from any source IP and Port to any destination IP and Port. Alert message,` "ICMP Ping Detected"`. Type 8 responds to an ICMP type request which is actually used in ping operations. SID is the unique identifier of the signature and rev 1 indicates the revision number for that rule.This is actually format used for snort signatures which is what suricata uses to generate alerts based off snort rules listed within suricata.

---


Step 5: Update Suricata Configuration
Open the suricata configuration file:

```bash
sudo nano
/etc/suricata/suricata.yaml
```

<img width="788" height="530" alt="Image" src="https://github.com/user-attachments/assets/a6e876c2-6fe0-45a5-8c38-c0a70e5bb5ab" />

Set the `default-rule-path` and include `local.rules` in the `rule-files` section.

---


Step 6: Apply the changes by restarting Suricata:
```bash
sudo systemctl restart suricata
```
---

Step 7: Run suricata to verify rules are loaded:
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -v
```
<img width="628" height="402" alt="Image" src="https://github.com/user-attachments/assets/33ce29c4-def0-47df-827a-024327bbd0cb" />

<img width="630" height="71" alt="Image" src="https://github.com/user-attachments/assets/027117f1-731f-490a-8f44-369e189c096c" />

---

Step 8:Generate traffic to trigger the rule:
```bash
ping -c 4 8.8.8.8
```

<img width="562" height="193" alt="Image" src="https://github.com/user-attachments/assets/96405b7a-a498-41f9-8abb-53d78605fbcb" />

---


Step 9:Verify the detection in the Suricata logs
```bash
sudo cat /var/log/suricata/eve.json | grep "ICMP Ping Detected"
```
<img width="637" height="427" alt="Image" src="https://github.com/user-attachments/assets/21297b1b-29b2-4665-9735-711e70050fef" />

---

## Network Traffic Capture with Wireshark

Step 10: Setting up Wireshark to packet capture on  your network

<img width="742" height="357" alt="Image" src="https://github.com/user-attachments/assets/c32395e1-a689-440c-9015-a332ddabbda9" />


Wireshark filtering enables you to isolate specific traffic, helping you analyze network data more effectively.

<img width="752" height="303" alt="Image" src="https://github.com/user-attachments/assets/1a455715-94da-426e-b8ce-0091ad5d0d53" />

---

Step 11: Analyzing ICMP Traffic
Gained an understanding of how ICMP traffic, to test network reachability using ICMP Echo Request and responses (ICMP Echo Reply)

<img width="786" height="525" alt="Image" src="https://github.com/user-attachments/assets/bcfc441f-aa16-4c16-bcfe-10c619c1687f" />
