# CS366 - Internet of Things  

## Mitigation of Replay Attacks for Secure Downward in Static RPL Networks  

**Authors:**  
- Krishna Bhargav N (221CS228)  
- Himaneesh Y (221CS264)  

---

## Abstract  

The Routing Protocol for Low-Power and Lossy Networks (RPL) serves as the primary routing standard for IoT (Internet of Things) deployments, enabling data exchange across large-scale networks of constrained sensor nodes. However, the protocol’s design emphasis on simplicity and low control overhead introduces exploitable security weaknesses.  

This report focuses on one such vulnerability — the **DAO (Destination Advertisement Object) replay attack**. In this attack, an adversarial node records legitimate downward route advertisement messages (DAOs) and retransmits them at a high frequency. These repeated broadcasts corrupt the network’s routing state, consume limited energy and memory resources, and can lead to outdated or incorrect downward routes being maintained throughout the DODAG.  

To mitigate this threat, we design, implement, and evaluate a lightweight stateful defense mechanism termed the **Detection and Response Module (DRM)**. The DRM operates independently on each node, requiring no cryptographic primitives or additional protocol overhead, making it suitable for constrained IoT environments.  

Implemented as the `DrmComponent` class in the **ns-3 simulation framework**, the DRM inspects every incoming DAO packet. It computes a compact CRC16-based fingerprint of the DAO’s payload and maintains a per-neighbor cache of recent packet hashes and timestamps. Using this cache, the module identifies replayed or redundant DAOs through temporal and spatial correlation.  

Suspicion scores increase moderately for repeated packets from the same node (to accommodate genuine retransmissions) and sharply for duplicate packets received from multiple distinct sources. When a node’s suspicion score surpasses a configurable threshold (e.g., 5), it is temporarily blacklisted, and all subsequent DAO messages from it are ignored.  

The mitigation’s performance was validated through detailed simulation in a **20-node static grid topology** using ns-3. Two primary scenarios were analyzed:  
1. **Baseline Scenario (without protection)**  
2. **Protected Scenario (with DRM enabled)**  

An attacker node initiated a replay of captured DAO packets at a rate of 5 packets per second beginning at 12 seconds into the simulation.  

Results show the protected configuration rapidly detected replay behavior — the first blacklist event occurred **1.21 seconds after** the attack began. The DRM recorded **128 suspicious DAO events** and **blocked 451 replayed packets out of 512 total**, neutralizing the attack while maintaining minimal computational cost.  

This evaluation confirms that the proposed hash-and-blacklist–based DRM provides a **resource-efficient countermeasure** for securing static RPL networks against DAO replay attacks, ensuring routing consistency and resilience without heavy cryptographic techniques.  

---

## Issues Identified  

### Violation of Availability  
The replay of DAO messages effectively generates a “DAO Flood” or “Downward Path Saturation” attack. The attacker overwhelms parent nodes with redundant DAO transmissions, increasing control overhead and energy consumption. Limited IoT devices must continuously process these bogus updates, reducing operational lifetime and degrading responsiveness.  

### Violation of Integrity  
Replayed DAOs distort the routing tables of parent and root nodes. By injecting outdated or duplicated advertisements, attackers cause stale or incorrect routes, leading to misdelivery, loops, and invalid downward paths. This results in **40–60% degradation** in packet delivery ratio (PDR) under attack conditions.  

### Critical Impact Level  
Persistent DAO replays can cause legitimate routes to be discarded or redundant entries to flood routing tables, leading to network partitioning and service disruption. Thus, this is a **critical severity** issue undermining RPL’s downward traffic stability.  

---

## Proposed Solution  

### Detection and Response Module (DRM)  

Implemented as the `DrmComponent` C++ class within `dao.cc`, this lightweight node-level defense discards malicious packets and isolates suspicious nodes.  

#### Lightweight Packet Fingerprinting  
- Computes a CRC16 hash over DAO payloads.  
- Produces a compact 16-bit signature ideal for constrained devices.  

#### Stateful Neighbor Monitoring  
- Maintains a `m_neighbors` table tracking recent DAO hashes and timestamps (cache size: 8 per neighbor).  

#### Replay Detection Logic  
- **Same-Source Replay:**  
  Repeated DAO from same node increases suspicion probabilistically (30%).  
- **Cross-Source Replay:**  
  If DAO hash reappears from a different node, suspicion increases deterministically (100%).  

#### Suspicion Scoring and Temporary Blacklisting  
- Suspicion ≥ 5 → node blacklisted for 60 seconds.  
- All further DAOs from blacklisted nodes are dropped.  

#### Active Mitigation  
- Blacklisted nodes’ packets are dropped immediately;  
- `m_droppedDueToMitigation` counter tracks impact.  

**Highlights:**  
- ⚡ *Fast detection speed* (~1 second).  
- 🧠 *Resilient to false positives* using probabilistic replay tolerance.  
- 🛡️ *Effective mitigation* demonstrated in quantitative results.  

---

## Methodology  

The **ns-3 network simulator** models and evaluates the DAO replay attack and mitigation mechanism.  

### Experimental Setup  
- **Nodes:** 20 static nodes in grid topology (20 m spacing).  
- **Mobility:** Static (`ConstantPositionMobilityModel`).  
- **Network Stack:** Adhoc Wi-Fi MAC (6 Mbps), IPv4 (10.1.1.0/24).  
- **Applications:**  
  - **Root Node (0):** runs `DaoRootApp`, sends DAOs every 5s.  
  - **Attacker Node (19):** runs `AttackerApp`, captures and replays DAO packets.  
  - **All Nodes:** run `DrmComponent` for detection and mitigation.  

---

## Attack Simulation  

### Capture Phase  
- Attacker listens on UDP port 12345 and captures DAO packets from root.  

### Replay Phase  
- Starts at `attackStart = 12s`.  
- Attacker replays captured DAOs at 5 packets/s, flooding network with stale data.  

---

## Mitigation Mechanism Implementation  

The `DrmComponent` executes two experimental scenarios:  

1. **Baseline (Mitigation OFF):**  
   - `--disableRootProtection=true`  
   - DAO messages accepted without detection.  

2. **Protected (Mitigation ON):**  
   - `--disableRootProtection=false`  
   - Enables full DRM logic: hashing, suspicion scoring, and blacklisting.  

---

## Evaluation and Metrics  

Metrics collected:  
- **DAOs Dropped Due to Mitigation** — primary success indicator.  
- **Total Suspicious Events** — instances of anomaly detection.  
- **Total Blacklist Events** — count of blacklisted attackers.  
- **Detection Time (First Blacklist)** — time to first detection.  

---

## Code Implementation  

> 📂 *Refer to the file `dao.cc` in the GitHub repository for full implementation details.*  

This code defines three key classes:  

- `DrmComponent` – Detection & Response Module  
- `DaoSourceApp` – Simulates legitimate DAO transmissions  
- `AttackerApp` – Simulates adversarial DAO replays  

It also includes a `main()` function orchestrating the entire simulation and reporting network metrics.  

---

## Code Explanation  

### DrmComponent (Detection & Response Module)  
Handles replay detection, suspicion scoring, blacklisting, and logging.  
Maintains neighbor caches (`m_neighbors`), recent global hashes (`m_recentGlobal`), and last sequence numbers (`m_lastDaoSeq`).  

### DaoSourceApp (Root Node)  
Periodically sends legitimate DAO packets with incrementing `dao_seq`.  

### AttackerApp (Attacker Node)  
Captures a DAO and replays it at a high rate to simulate attack conditions.  

---

## Results and Analysis  

Two scenarios were compared:  

### **With Mitigation Enabled**  
Command:  
```bash
./ns3 --run "scratch/dao"
