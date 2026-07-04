# 🕸️ ByteSnare v1.0.0 (NetGuard_AI Core)

██████╗ ██╗   ██╗████████╗███████╗███████╗███╗   ██╗ █████╗ ██████╗ ███████╗
██╔══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔════╝
██████╔╝ ╚████╔╝    ██║   █████╗  ███████╗██╔██╗ ██║███████║██████╔╝█████╗
██╔══██╗  ╚██╔╝     ██║   ██╔══╝  ╚════██║██║╚██╗██║██╔══██║██╔══██╗██╔══╝
██████╔╝   ██║      ██║   ███████╗███████║██║ ╚████║██║  ██║██║  ██║███████╗
╚══════╝   ╚═╝      ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝

[![Kernel-Level Sniffing](https://img.shields.io/badge/Socket-Raw%20L2%2FL3-red.svg)]()
[![Defense Architecture](https://img.shields.io/badge/Architecture-Asynchronous%20SIEM-orange.svg)]()
[![Environment](https://img.shields.io/badge/Environment-Linux%20Kernel%205.x%2B-blue.svg)]()
[![Security Policy](https://img.shields.io/badge/Policy-Strict%20Academic%20Audit-brightgreen.svg)]()

**ByteSnare** is an advanced, high-performance Network Intrusion Detection System (NIDS) and adaptive cyber-defense engine. Operating at the raw socket layer, the system performs real-time Deep Packet Inspection (DPI), dynamic firewall state manipulation, and automated threat isolation through localized honey-services.

---


[![Kernel-Level Sniffing](https://img.shields.io/badge/Socket-Raw%20L2%2FL3-red.svg)]()
[![Defense Architecture](https://img.shields.io/badge/Architecture-Asynchronous%20SIEM-orange.svg)]()
[![Environment](https://img.shields.io/badge/Environment-Linux%20Kernel%205.x%2B-blue.svg)]()
[![Security Policy](https://img.shields.io/badge/Policy-Strict%20Academic%20Audit-brightgreen.svg)]()

**ByteSnare** is an advanced, high-performance Network Intrusion Detection System (NIDS) and adaptive cyber-defense engine. Operating at the raw socket layer, the system performs real-time Deep Packet Inspection (DPI), dynamic firewall state manipulation, and automated threat isolation through localized honey-services.

---

## 🏗️ System Architecture & Data Flow

```text
       [ RAW NETWORK INGESTION ]
                  │
                  ▼
       ┌────────────────────┐
       │   ByteSnare.py     │ ──► [ Layer 2/3 Packet Dissection ]
       └─────────┬──────────┘
                 │ (Malicious Signature Triggered)
                 ▼
       ┌────────────────────┐
       │ shadownet/ Core    │
       └─┬─────────┬───────┬┘
         │         │       │
         ▼         ▼       ▼
   ┌───────────┐┌───────────┐┌───────────────┐
   │firewall.py││ logger.py ││ decoy_server.py│
   └─────┬─────┘└─────┬─────┘└───────┬───────┘
         │            │              │
         ▼            ▼              ▼
   [Netfilter/   [SIEM Log    [Anti-Recon OS
    IPTables]    Ingestion]    Spoofing]
```
🛰️ Subsystem Blueprint & Specifications
🔬 Core Ingestion & Analysis
ByteSnare.py: Engineered around a non-blocking raw socket loop. Extracts IP/TCP/UDP/ICMP primitives and evaluates payloads against dynamic threat thresholds.

network_config.json & config.yaml: Centralized cryptographic hashes, port bindings, rate limits, and network interface hooks.

🛡️ The ShadowNet Framework (shadownet/)
firewall.py: Interacts directly with Linux kernel networking tables to dynamically inject drop rules for identified attacking IPs.

decoy_server.py & banner_spoofer.py: Deploys intelligent, low-interaction honeypots to catch automated scanners and spoof banner signatures to confuse reconnaissance modules.

honeyfile_monitor.py: Monitors system integrity and traps lateral traversal attempts via Linux filesystem events.

logger.py & models.py: Structures multi-threaded alert pipelines into standardized, SIEM-ready log structures (logs/shadownet.log).

## 📊 Technical Capabilities Matrix

| Vector Capability | Mechanism | Operational Layer | Overhead Impact |
| :--- | :--- | :--- | :--- |
| **Deep Packet Inspection** | Native Socket Dissection | L2 / L3 / L4 Data | Minimal (< 2% CPU) |
| **Dynamic Containment** | Kernel Netfilter Dropping | Linux IP Tables / Firewall | Instantaneous |
| **Deception Routing** | Banner Spoofing & Decoys | Application Emulation | Low footprint |
| **State Logging** | Async Threaded IO | SQLite File Registry | Isolated |

🛠️ Deployment Blueprint
Provisioning the Laboratory Environment
The framework requires native Linux compilation tools, superuser execution capabilities, and Python 3.10+.

```Bash
# Clone down the operational suite
git clone [https://github.com/0xEnki/bytesnare.git](https://github.com/0xEnki/bytesnare.git)
cd bytesnare

# Initialize environment & apply executable bit to automated provisioner
chmod +x install.sh
sudo ./install.sh
```
Production Runtime Vectors
To initialize the primary network capture loop alongside the background microservices:
```Bash
sudo python3 ByteSnare.py
```
To strictly spin up standalone active defense honeypots for decoy metrics:
```Bash
sudo python3 -m shadownet.decoy_server
```
⚠️ Operational Security Directive
[!WARNING]

INTELLECTUAL COMPLIANCE & LEGAL NOTICE: This system is explicitly engineered for authorized defensive network architecture auditing, institutional research, and trusted system hardening. Deploying this agent against infrastructural targets without definitive, written prior authorization is strictly prohibited. The developer assumes absolutely no liability for infrastructural down-time or compliance violations.
