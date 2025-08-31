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
   Monitored specific network interfaces in real time to identify and stop attacks..
---

## OBJECTIVE

This project involved the design and execution of a comprehensive series of network security simulations using `Wireshark` in a controlled virtual lab environment. Leveraging `VirtualBox` and multiple `Linux` virtual machines, I captured and analyzed network traffic across a variety of protocols to simulate both normal and malicious behavior. Key scenarios included `TCP handshakes`, `SYN scans`, `Telnet/SSH` sessions, and `DoS` indicators. Each simulation was crafted to mirror real-world attack patterns or defensive monitoring tasks, providing deep insights into packet-level behavior, protocol vulnerabilities, and network-based threat detection techniques. This project demonstrated hands-on proficiency in packet analysis, threat simulation, and network forensic workflows.

---

## 📜 TABLE OF CONTENTS

- [`DETECTING AND ANALYSING TRAFFIC WITH SURICATA`](#packet-analysis-with-suricata)
- [`TELNET TRAFFIC`](#telnet-traffic)
- [`SSH TRAFFIC`](#ssh-traffic)
- [`TCP 3-WAY HANDSHAKE`](#tcp-3-way-handshake)
- [`DOS ATTACK SIMULATION`](#dos-attack-simulation)

---


## DETECTING AND ANALYSING TRAFFIC WITH SURICATA

<img width="597" height="303" alt="Image" src="https://github.com/user-attachments/assets/74c3c280-3d46-4d89-907f-75ed57c23cb6" />

---
### Step 1. Prepare the Environment, using ` Kali Linux `as the Operating System. Setup Kali Linux on a Virtual Machine using virtualBox.

<img width="640" height="562" alt="Image" src="https://github.com/user-attachments/assets/31055b3a-bd46-4beb-9005-e10b2abb4b86" />

---

### Step2. Install Suricata on the Kali Linux Operating System. Open the terminal and update the package list:
```bash
sudo apt update
```
- ### To install and configure `Suricata `on `Kali Linux`, to act as an Intrusion Detection System

```bash
sudo apt install suricata
```
<img width="606" height="230" alt="Image" src="https://github.com/user-attachments/assets/f0152a07-e95e-4ea5-9682-e66d987cf703" />

---

### Step 3. Update the Suricata rule set:
```bash
sudo suricata-update
```
<img width="797" height="562" alt="Image" src="https://github.com/user-attachments/assets/c4c4aca3-0a36-4927-9bea-db6aeb08cbf4" />

---

### Step 4: Next, create a custom rule
- ### Open the local.rule file in GNU nano editor

```bash
sudo nano
/var/lib/suricata//rules/local.rules
```

<img width="545" height="67" alt="Image" src="https://github.com/user-attachments/assets/fd208556-88ac-4e13-8bca-352a38231d86" />

- ### After adding custom rules, Add the rule to detect ICMP ping requests:

```bash
alert icmp any any -> any any (msg:"ICMP Ping Dectected"; itype:8; sid:1000001; rev:1;)
```

<img width="800" height="597" alt="Image" src="https://github.com/user-attachments/assets/51329592-92f1-423a-b8ec-482ce1454581" />

Generate an alert on ICMP from any source IP and Port to any destination IP and Port. Alert message,` "ICMP Ping Detected"`. Type 8 responds to an ICMP type request which is actually used in ping operations. SID is the unique identifier of the signature and rev 1 indicates the revision number for that rule.This is actually format used for snort signatures which is what suricata uses to generate alerts based off snort rules listed within suricata.


---


### Step 5: Update Suricata Configuration
- ### Open the suricata configuration file:

```bash
sudo nano
/etc/suricata/suricata.yaml
```

<img width="788" height="530" alt="Image" src="https://github.com/user-attachments/assets/a6e876c2-6fe0-45a5-8c38-c0a70e5bb5ab" />

- ### Set the `default-rule-path` and include `local.rules` in the `rule-files` section.

---


### Step 6: Apply the changes by restarting Suricata:
```bash
sudo systemctl restart suricata
```

---


### Step 7: Run suricata to verify rules are loaded:
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -v
```
<img width="628" height="402" alt="Image" src="https://github.com/user-attachments/assets/33ce29c4-def0-47df-827a-024327bbd0cb" />

<img width="630" height="71" alt="Image" src="https://github.com/user-attachments/assets/027117f1-731f-490a-8f44-369e189c096c" />

---

### Step 8:Generate traffic to trigger the rule:
```bash
ping -c 4 8.8.8.8
```

<img width="562" height="193" alt="Image" src="https://github.com/user-attachments/assets/96405b7a-a498-41f9-8abb-53d78605fbcb" />

---


### Step 9:Verify the detection in the Suricata logs
```bash
sudo cat /var/log/suricata/eve.json | grep "ICMP Ping Detected"
```
<img width="637" height="427" alt="Image" src="https://github.com/user-attachments/assets/21297b1b-29b2-4665-9735-711e70050fef" />

---


## Network Traffic Capture with Wireshark

### Step 10: Setting up Wireshark to packet capture on  your network

<img width="742" height="357" alt="Image" src="https://github.com/user-attachments/assets/c32395e1-a689-440c-9015-a332ddabbda9" />


- ### Wireshark filtering enables you to isolate specific traffic, helping you analyze network data more effectively.

<img width="752" height="303" alt="Image" src="https://github.com/user-attachments/assets/1a455715-94da-426e-b8ce-0091ad5d0d53" />

---

### Step 11: Analyzing ICMP Traffic
- ### Gained an understanding of how ICMP traffic, to test network reachability using ICMP Echo Request and responses (ICMP Echo Reply)

<img width="786" height="525" alt="Image" src="https://github.com/user-attachments/assets/bcfc441f-aa16-4c16-bcfe-10c619c1687f" />

*This project demonstrates suricata's role in network monitoring and intrusion detection . knowledge in writing and deploying custom rules in suricata to trigger alerts for ICMP ping attacks.
Understanding how to simulate , filter traffic and capture various real-world network security scenarios  using `Wireshark`*

---

## TELNET TRAFFIC

### Step 1: Set Up the `Telnet Server` (VM 2)

- ### Update package list:
```bash
sudo apt update
```
- ### Install Telnet server (telnetd):
```bash
sudo apt install telnetd
```
- ### Start the Telnet service:
```bash
sudo systemctl start inetd
```
- ### Confirm that Telnet is listening on port 23:
```bash
sudo netstat -tuln | grep :23
```

<img width="717" height="54" alt="image" src="https://github.com/user-attachments/assets/287643b2-218f-4888-9c4f-3327ef279151" />

### *Start `Wireshark` and begin capturing on `enp0s3`.*

---

### Step 2: Set up the `Telnet Client` (VM 1) 

- ### Install the Telnet Client:
```bash
sudo apt install telnet
```

- ### Connect to the Telnet server using its IP address:
```bash
telnet 10.10.10.50
```

<img width="617" height="415" alt="Lab 52" src="https://github.com/user-attachments/assets/b2c8d8fd-3857-4cfa-b41e-28386c5171eb" /></br>

- ### Once connected, run commands to generate traffic:
```bash
whoami
uname -a
ls -la
uptime
```

<img width="726" height="559" alt="Lab 59" src="https://github.com/user-attachments/assets/2652131c-4977-4180-9871-cc4b0463c7ff" />

---

### Step 3: Analyze Telnet Traffic in `Wireshark`

- ### Apply the display filter: `telnet` or `tcp.port == 23`

<img width="1425" height="646" alt="Lab 54 Crop" src="https://github.com/user-attachments/assets/30604382-6420-43aa-86ae-cbd85cc6697c" /></br>

The Telnet session captured in Wireshark demonstrates the inherent insecurity of the protocol, which transmits data entirely in plaintext over TCP port 23. During the session, we observed the full login exchange between the client and server, including the `Ubuntu login:` prompt followed by the username `test` and the password `9000`, all visible without encryption. Subsequent commands such as `whoami`, `uname -a`, `ls -la`, and `uptime` were also captured in clear text, along with their corresponding responses. This analysis clearly highlights how Telnet traffic can be easily intercepted and read by anyone with access to the network, reinforcing why Telnet is considered insecure and has been replaced in modern systems by encrypted alternatives like SSH.

<img width="863" height="489" alt="Lab 55" src="https://github.com/user-attachments/assets/a438edd4-b14d-4fc6-9353-d354d4e0c40f" />

---
</br>



## SSH TRAFFIC

### Step 1: Configure the SSH Server

- ### On the server VM, install and verify the SSH service:
```bash
sudo apt update
sudo apt install openssh-server
sudo systemctl status ssh
```

<img width="725" height="289" alt="Lab 57" src="https://github.com/user-attachments/assets/d0c89cb6-5067-41f9-b534-057d1ea4392b" />

### *Start `Wireshark` and begin capturing on `enp0s3`.*

---

### Step 2: Connect the SSH Client

- ### On the client VM, initiate an SSH session to the server:
```bash
ssh test@10.10.10.50
```

<img width="731" height="400" alt="Lab 58" src="https://github.com/user-attachments/assets/465d6b8b-4e1c-46d4-be6c-a2c882faef10" /></br>

- ### While connected, execute commands to generate traffic:
```bash
whoami
uname -a
ls -la
uptime
```

<img width="726" height="559" alt="Lab 59" src="https://github.com/user-attachments/assets/98bb9cd3-c20a-4816-9aae-a94cd1ea563a" />

---

### Step 3: Analyze SSH Traffic in `Wireshark`

- ### Apply the display filter: `tcp.port == 22`

<img width="1454" height="596" alt="Lab 60" src="https://github.com/user-attachments/assets/4ba492fe-01f1-4365-a540-f6c1f27c75e1" /></br>

When reviewing the SSH session in Wireshark, we observed that all communication between the client and server was encrypted. Unlike `Telnet`, which transmits data (including usernames and passwords) in plaintext, `SSH` encapsulates all authentication and session data within encrypted packets, making it unreadable to observers. In the capture, the initial handshake involves key exchange and algorithm negotiation, followed by encrypted `TCP` segments on `port 22`. Even commands like `whoami` or `ls -la` and their responses are not visible in plaintext, showcasing SSH's effectiveness in providing secure remote access and protecting against eavesdropping.

---


## TCP 3-WAY HANDSHAKE



### Step 4: Analyze the `TCP 3-Way Handshake` and `SYN Scan` in Wireshark

- ### Apply the display filter: `tcp.port == 1234`

<img width="1423" height="203" alt="Lab 24" src="https://github.com/user-attachments/assets/d4b96623-db7b-491d-9237-ff689a0a6044" /></br>

During the normal TCP 3-way handshake test, we observed the expected packet exchange pattern: the `client initiated a connection with a SYN packet`, the `server responded with SYN-ACK`, and the `client completed the handshake with an ACK`. This sequence confirms a fully established TCP session on `port 1234`, visible in Wireshark using the `tcp.port == 1234` filter.

<img width="1204" height="55" alt="Lab 25" src="https://github.com/user-attachments/assets/2d5d6405-8cae-48f1-8457-1a370978650d" /></br>

In contrast, the SYN scan test using `nmap -sS` demonstrated a half-open connection. The `client sent a SYN`, the `server replied with SYN-ACK`, but instead of completing the handshake, the `client responded with an immediate RST`. This is characteristic of stealth scanning techniques often used by attackers to detect open ports without fully establishing a connection.

---

## DoS ATTACK SIMULATION

### Step 1: Install Network Utilities and Monitoring Tools

- ### Install tools and Wireshark on both VMs:
```bash
sudo apt update
sudo apt install iputils-ping hping3 wireshark -y
```

### *Start `Wireshark` and begin capturing on `enp0s3`.*

---

### Step 2: Execute a Fast Flood Ping Attack

- ### From the Client, execute this command to the Server:
```bash
sudo ping -f 10.10.10.50
```

<img width="725" height="123" alt="Lab 26" src="https://github.com/user-attachments/assets/0cb6f93c-6ecd-41f7-b5a7-2f7e01e2d312" />

---

### Step 3: Monitor System and Network Resource Usage During Simulated Attack

- ### Use `top` to launch a real-time system monitoring showing CPU, memory, and process usage:
```bash
top
```

<img width="719" height="505" alt="Lab 28" src="https://github.com/user-attachments/assets/19c880e8-e899-461c-8f5e-c1197c5b7a0d" />

- ### Install and use `iftop` to monitor bandwidth usage:
```bash
sudo apt install iftop
sudo iftop -i enp0s3
```

<img width="725" height="506" alt="Lab 29" src="https://github.com/user-attachments/assets/50338e51-18bb-478d-8775-d5673e3e4458" />

- ### Install and use `nload` to monitor incoming/outgoing traffic:
```bash
sudo apt install iftop
sudo iftop -i enp0s3
```

<img width="723" height="506" alt="Lab 30" src="https://github.com/user-attachments/assets/d726ad5d-0fde-4bea-8229-6e1e3ba12528" />

---

### Step 3: Analyze the `DoS Attack` in Wireshark

<img width="1472" height="781" alt="Lab 27" src="https://github.com/user-attachments/assets/d2f2c75e-0275-471c-8c60-84c719c7f316" /></br>

The purpose of this simulated DoS attack was to demonstrate how excessive `ICMP` traffic can overwhelm a target system and be identified using Wireshark and monitoring tools. In this setup, the attacker VM (`10.10.10.100`) flooded the victim VM (`10.10.10.50`) with high-speed ping requests using `ping -f`, simulating a basic `ICMP flood` attack. As a result, Wireshark recorded a total of `26,170` ICMP packets in `5 seconds`, consisting of both echo requests and replies. This volume of traffic visibly increased network and CPU load on the victim, effectively modeling how even a single host can disrupt service availability. The simulation allowed for real-time visibility into attack patterns and reinforced the importance of detecting early indicators of denial-of-service behavior.

---

*This project demonstrates how to simulate and capture various real-world network security scenarios using `Wireshark`, including plaintext protocol leaks, encrypted communication, handshakes, and denial-of-service behaviors. Each simulation helps visualize how different attacks and protocol behaviors appear in packet captures, enhancing my skills in traffic analysis, threat detection, and network forensics.*


