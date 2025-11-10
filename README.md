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

In one representative run the attacker replayed captured DAO packets at 5 packets/s beginning at 12 s. The protected configuration identified replay behavior rapidly — the first blacklist event occurred **1.21 seconds after** the attack began (at 13.21 s). The DRM recorded **128 suspicious DAO events** and **blocked 451 replayed packets out of 512 total**, effectively neutralizing the adversarial impact while maintaining minimal computational cost.

This evaluation confirms that the proposed hash-and-blacklist–based DRM provides a **resource-efficient countermeasure** for securing static RPL networks against DAO replay attacks, ensuring routing consistency and resilience without heavy cryptography.

---

## Issues Identified

### Violation of Availability
The replay of DAO messages effectively generates a “DAO Flood” or “Downward Path Saturation” attack. The attacker overwhelms parent nodes with redundant DAO transmissions, increasing control overhead and energy consumption. Constrained IoT devices must continuously process these bogus updates, reducing operational lifetime and degrading responsiveness.

### Violation of Integrity
Replayed DAOs distort the routing tables of parent and root nodes. By injecting outdated or duplicated advertisements, attackers cause stale or incorrect routes, leading to misdelivery, loops, and invalid downward paths. This results in **40–60% degradation** in packet delivery ratio (PDR) under attack conditions in comparable scenarios.

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
- **Same-Source Replay:** repeated DAO from same node increases suspicion probabilistically (30%) to tolerate legitimate retransmissions.
- **Cross-Source Replay:** if the same DAO hash is observed from a different sender within a short window, suspicion increases deterministically.

#### Suspicion Scoring and Temporary Blacklisting
- Suspicion ≥ 5 → node blacklisted for 60 seconds.
- All further DAOs from blacklisted nodes are dropped.

#### Active Mitigation
- Blacklisted nodes’ packets are dropped immediately.
- `m_droppedDueToMitigation` counter tracks mitigation drops.

**Highlights:**  
- Fast detection (~1 second for high-frequency attackers).  
- Resilient to false positives via probabilistic tolerance for same-source duplicates.  
- Effective suppression of replay traffic demonstrated in ns-3 experiments.

---

## Methodology

The **ns-3 network simulator** models and evaluates the DAO replay attack and mitigation mechanism.

### Experimental Setup
- **Nodes:** 20 static nodes in a grid topology (20 m spacing).  
- **Mobility:** Static (`ConstantPositionMobilityModel`).  
- **Network Stack:** Adhoc Wi-Fi MAC (6 Mbps), IPv4 (10.1.1.0/24).  
- **Applications:**  
  - **Root Node (0):** runs `DaoSourceApp`, sends DAOs periodically (example runs used 3–5 s intervals).  
  - **Attacker Node:** runs `AttackerApp`, captures and replays DAO packets.  
  - **All Nodes:** run `DrmComponent` (except attacker node in some configurations).

---

## Attack Simulation

### Capture Phase
Attacker listens on UDP port 12345 and captures DAO payloads broadcast by the root.

### Replay Phase
At `attackStart` (e.g., 8–12 s depending on run), the attacker begins replaying the captured DAO at a configured rate (e.g., 5–10 packets/s), optionally applying small perturbations to attempt evasion. Replays are broadcast to the network to maximize impact.

---

## Mitigation Mechanism Implementation

The `DrmComponent` executes two experimental scenarios:

1. **Baseline (Mitigation OFF):**
   - `--disableRootProtection=true`
   - DAO messages accepted and hashed only for bookkeeping; no detection or blacklisting occurs.

2. **Protected (Mitigation ON):**
   - `--disableRootProtection=false`
   - Full DRM logic enabled: CRC16 hashing, per-neighbor caches, global recent-hash map, DAO-sequence checking, suspicion scoring, and timed blacklisting.

---

## Evaluation and Metrics

Metrics collected across DRM instances:
- **Total DAOs sent by source**  
- **Total DAOs received (all nodes)**  
- **DAOs dropped (all nodes)**  
- **DAOs dropped due to mitigation** (DRM-caused drops)  
- **Total suspicious events** (suspicion increments)  
- **Total blacklist events**  
- **Detection time (first blacklist)**  
- **Per-node: Received, Dropped, Suspicious, Blacklists, First blacklist time**

These metrics allow assessment of mitigation effectiveness, responsiveness, and false-positive behavior.

---

## Results

> 📂 *Full implementation and code live in* `dao.cc` *in the repository — refer there for exact lines and runtime configuration.*

Two representative result summaries from different runs/configurations are provided (document contains multiple experiment variants):

### Example Run — Protected (reported in Results section)
