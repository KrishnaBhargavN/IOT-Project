 #include "ns3/core-module.h"
 #include "ns3/network-module.h"
 #include "ns3/internet-module.h"
 #include "ns3/wifi-module.h"
 #include "ns3/mobility-module.h"
 #include "ns3/udp-socket-factory.h"
 #include "ns3/yans-wifi-helper.h"
#include "ns3/wifi-mac-helper.h"
#include "ns3/wifi-helper.h"
 
 #include <sstream>
 #include <vector>
 #include <map>
 #include <string>
 #include <cstdlib>
 #include <ctime>
 #include <algorithm>
 
 using namespace ns3;
 NS_LOG_COMPONENT_DEFINE("RplDaoReplayDemo");
 
 // ===================================================
 // Helper: CRC16 (XMODEM)
 // ===================================================
 static uint16_t
 Crc16(const uint8_t *data, size_t len)
 {
   uint16_t crc = 0x0000;
   for (size_t i = 0; i < len; ++i) {
     crc ^= (uint16_t)data[i] << 8;
     for (int j = 0; j < 8; ++j) {
       crc = (crc & 0x8000) ? (crc << 1) ^ 0x1021 : crc << 1;
     }
   }
   return crc & 0xFFFF;
 }
 
 // ===================================================
 // DRM (Detection & Response Module) - DAO-focused
 // ===================================================
 struct DrmNeighborInfo {
   uint16_t dao_hash[8];
   Time dao_ts[8];
   uint8_t cache_idx = 0;
   uint8_t suspicion = 0;
   Time blacklist_until = Seconds(0);
   Time last_seen = Seconds(0);
   DrmNeighborInfo() {
     for (int i = 0; i < 8; ++i) dao_hash[i] = 0;
     for (int i = 0; i < 8; ++i) dao_ts[i] = Seconds(0);
   }
 };
 
 class DrmComponent : public Object {
 public:
   DrmComponent(Ptr<Node> node) : m_node(node) {}
   void Setup(Ptr<Ipv4> ipv4);
   void SetRootIp(const std::string &rootIp) { m_rootIp = rootIp; }
   void SetDisableRootProtection(bool v) { m_disableRootProtection = v; }
   void SendDaoBroadcast(const std::vector<uint8_t>& payload);
   void RecvDao(Ptr<Socket> sock);
   uint32_t GetControlDaoCount() const { return m_controlDaoCount; }
   uint32_t GetDroppedDaoCount() const { return m_droppedDaoCount; }
 
   // Metrics getters
   uint32_t GetSuspiciousEvents() const { return m_suspiciousEvents; }
   uint32_t GetBlacklistCount() const { return m_blacklistCount; }
   Time GetFirstBlacklistTime() const { return m_firstBlacklistTime; }
   uint32_t GetTotalReceived() const { return m_totalReceived; }
   uint32_t GetDroppedDueToMitigation() const { return m_droppedDueToMitigation; }
   uint8_t GetSuspicionForNode(const std::string &ip) {
       return m_neighbors.count(ip) ? m_neighbors.at(ip).suspicion : 0;
   }
 
 private:
   void PruneGlobal(Time now);
 
   Ptr<Node> m_node;
   Ptr<Ipv4> m_ipv4;
   Ptr<Socket> m_socket;
   std::map<std::string, DrmNeighborInfo> m_neighbors;
   std::map<uint16_t, std::pair<std::string, Time>> m_recentGlobal;
 
   // New: track last dao_seq per sender (strong anti-replay)
   std::map<std::string, uint8_t> m_lastDaoSeq;
 
   uint32_t m_controlDaoCount = 0;
   uint32_t m_droppedDaoCount = 0;
   uint64_t m_recvCounter = 0;
   std::string m_rootIp;
   bool m_disableRootProtection = false;
 
   // Metrics added
   uint32_t m_suspiciousEvents = 0;
   uint32_t m_blacklistCount = 0;
   Time m_firstBlacklistTime = Seconds(-1);
   uint32_t m_totalReceived = 0;
 
   // Count only drops caused by DRM mitigation (blacklist/replay)
   uint32_t m_droppedDueToMitigation = 0;
 };
 
 void
 DrmComponent::Setup(Ptr<Ipv4> ipv4)
 {
   m_ipv4 = ipv4;
   TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
   m_socket = Socket::CreateSocket(m_node, tid);
   InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), 12345);
   m_socket->Bind(local);
   m_socket->SetRecvCallback(MakeCallback(&DrmComponent::RecvDao, this));
 }
 
 void
 DrmComponent::SendDaoBroadcast(const std::vector<uint8_t>& payload)
 {
   Ptr<Socket> tx = Socket::CreateSocket(m_node, UdpSocketFactory::GetTypeId());
   tx->SetAllowBroadcast(true);
   InetSocketAddress dst = InetSocketAddress(Ipv4Address("255.255.255.255"), 12345);
   tx->Connect(dst);
   Ptr<Packet> p = Create<Packet>(payload.data(), payload.size());
   tx->Send(p);
   tx->Close();
   m_controlDaoCount++;
 }
 
 void
 DrmComponent::RecvDao(Ptr<Socket> sock)
 {
   Address from;
   Ptr<Packet> packet = sock->RecvFrom(from);
   InetSocketAddress addr = InetSocketAddress::ConvertFrom(from);
   Ipv4Address src = addr.GetIpv4();
   std::ostringstream oss; oss << src; std::string key = oss.str();
 
   uint32_t pktSize = packet->GetSize();
   if (pktSize == 0) {
     return;
   }
   std::vector<uint8_t> buf(pktSize);
   packet->CopyData(buf.data(), pktSize);
   uint16_t h = Crc16(buf.data(), buf.size());
   Time now = Simulator::Now();
   m_recvCounter++;
 
   // metric: total received DAOs by this DRM
   m_totalReceived++;

   // Log all received DAOs
   NS_LOG_INFO("Node " << m_node->GetId() << " received DAO from " << key 
               << " seq=" << (buf.empty() ? 0 : (unsigned)buf[0])
               << " hash=" << h << " at t=" << now.GetSeconds());
 
   auto it = m_neighbors.find(key);
   if (it == m_neighbors.end()) m_neighbors[key] = DrmNeighborInfo();
   DrmNeighborInfo &info = m_neighbors[key];
 
   // If mitigation is disabled, simply accept and store the hash (no detection)
   if (m_disableRootProtection) {
     // store for completeness (so neighbor stats still exist)
     info.dao_hash[info.cache_idx] = h;
     info.dao_ts[info.cache_idx] = now;
     info.cache_idx = (info.cache_idx + 1) % 8;
     NS_LOG_INFO("Node " << m_node->GetId() << " (DRM disabled) accepted DAO from " << key);
     return;
   }
 
   // BLACKLIST CHECK
   if (info.blacklist_until > now) {
     NS_LOG_WARN("Node " << m_node->GetId() << " DROPPED DAO from " << key << " (blacklisted until " 
                 << info.blacklist_until.GetSeconds() << "s)");
     m_droppedDaoCount++;
     m_droppedDueToMitigation++;
     return;
   }
 
   // DAO SEQUENCE CHECK (strong anti-replay)
   // We expect the first payload byte to be the dao_seq if payload length >= 1
   if (!buf.empty()) {
     uint8_t dao_seq = buf[0]; // interpret first byte as sequence
     auto seqIt = m_lastDaoSeq.find(key);
     if (seqIt != m_lastDaoSeq.end()) {
       uint8_t last_seq = seqIt->second;
       // If sequence is not strictly greater, treat as stale/replay
       if (dao_seq <= last_seq) {
         NS_LOG_WARN("Node " << m_node->GetId() << " detected stale/non-fresh DAO seq from " << key
                             << " seq=" << (unsigned)dao_seq << " last=" << (unsigned)last_seq
                             << " at t=" << now.GetSeconds());
         info.suspicion++;
         m_suspiciousEvents++;
         if (info.suspicion >= 5) {
           info.blacklist_until = now + Seconds(60);
           m_blacklistCount++;
           if (m_firstBlacklistTime == Seconds(-1)) {
             m_firstBlacklistTime = now;
           }
           NS_LOG_WARN("Node " << m_node->GetId() << " BLACKLISTED " << key 
                       << " (seq abuse, suspicion=" << (int)info.suspicion << ")");
         }
         m_droppedDaoCount++;
         m_droppedDueToMitigation++;
         return;
       }
     }
     // update last sequence (do this only after passing monotonicity)
     m_lastDaoSeq[key] = dao_seq;
   }
 
   // GLOBAL DUPLICATE DETECTION (cross-source)
   auto g = m_recentGlobal.find(h);
   if (g != m_recentGlobal.end() && (now - g->second.second) < Seconds(60)) {
     std::string lastSrc = g->second.first;
     if (lastSrc != key) {
       NS_LOG_WARN("Node " << m_node->GetId() << " detected cross-source replay: " << key << " vs " << lastSrc);
       info.suspicion++;
       m_suspiciousEvents++;
       if (info.suspicion >= 5) {
         info.blacklist_until = now + Seconds(60);
         m_blacklistCount++;
         if (m_firstBlacklistTime == Seconds(-1)) {
           m_firstBlacklistTime = now;
         }
         NS_LOG_WARN("Node " << m_node->GetId() << " BLACKLISTED " << key);
       }
       m_droppedDaoCount++;
       m_droppedDueToMitigation++;
       return;
     }
   }
   m_recentGlobal[h] = {key, now};
 
   // SAME-SOURCE DUPLICATE CHECK
   bool dup = false;
   for (int i = 0; i < 8; ++i) {
     if (info.dao_hash[i] == h && (now - info.dao_ts[i]) < Seconds(60)) {
       dup = true;
       break;
     }
   }
 
   if (dup) {
     double r = (std::rand() % 10000) / 100.0;
     if (r < 30.0) { // 30% chance to increment suspicion (tolerate retransmits)
       info.suspicion++;
       m_suspiciousEvents++;
       NS_LOG_WARN("Node " << m_node->GetId() << " suspicious same-source DAO from " << key
                           << " susp=" << (int)info.suspicion);
       if (info.suspicion >= 5) {
         info.blacklist_until = now + Seconds(60);
         m_blacklistCount++;
         if (m_firstBlacklistTime == Seconds(-1)) {
           m_firstBlacklistTime = now;
         }
         NS_LOG_WARN("Node " << m_node->GetId() << " BLACKLISTED " << key);
       }
     }
     m_droppedDaoCount++;
     m_droppedDueToMitigation++;
     return;
   } else {
     // accept DAO: store hash + timestamp
     info.dao_hash[info.cache_idx] = h;
     info.dao_ts[info.cache_idx] = now;
     info.cache_idx = (info.cache_idx + 1) % 8;
     NS_LOG_INFO("Node " << m_node->GetId() << " ACCEPTED DAO from " << key
                         << " (seq=" << (unsigned)m_lastDaoSeq[key] << ", hash=" << h << ")");
   }
 }
 
 void
 DrmComponent::PruneGlobal(Time now)
 {
   for (auto it = m_recentGlobal.begin(); it != m_recentGlobal.end();) {
     if ((now - it->second.second) > Seconds(60)) it = m_recentGlobal.erase(it);
     else ++it;
   }
 }
 
 // ===================================================
 // DaoSourceApp (root/source node for DAO-like packets)
 // ===================================================
 class DaoSourceApp : public Application {
 public:
   DaoSourceApp() {}
   void Setup(Ptr<DrmComponent> drm, Time interval, bool deterministic) {
     m_drm = drm; m_interval = interval; m_deterministic = deterministic;
     m_seq = 0;
   }
   void StartApplication() override { SendDao(); }
   void StopApplication() override { Simulator::Cancel(m_event); }
 
 private:
   void SendDao() {
     // Build an 8-byte payload. Byte 0 is dao_seq.
     uint8_t payload[8];
     payload[0] = (uint8_t)(m_seq++); // wrap-around allowed (uint8_t)
     if (m_deterministic) {
       uint8_t fixed[7] = {0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44};
       memcpy(&payload[1], fixed, 7);
     } else {
       for (int i = 1; i < 8; ++i) payload[i] = std::rand() % 256;
     }
     std::vector<uint8_t> vec(payload, payload + 8);
     m_drm->SendDaoBroadcast(vec);
     NS_LOG_WARN("SOURCE sent DAO (seq=" << (unsigned)payload[0] << " hash=" << Crc16(vec.data(), vec.size())
                  << ") at t=" << Simulator::Now().GetSeconds());
     m_event = Simulator::Schedule(m_interval, &DaoSourceApp::SendDao, this);
   }
   Ptr<DrmComponent> m_drm;
   EventId m_event;
   Time m_interval;
   bool m_deterministic;
   uint8_t m_seq;
 };
 
 // ===================================================
 // Attacker (captures and replays DAO-like payloads)
 // ===================================================
 class AttackerApp : public Application {
    public:
      AttackerApp() : m_replayCount(0), m_captureCount(0) {}
      void Setup(Ptr<Node> node, double rate, Time start, bool perturb) {
        m_node = node; m_rate = rate; m_start = start; m_perturb = perturb;
      }
      void StartApplication() override {
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        
        // Create a SEPARATE socket just for receiving/capturing
        m_recvSocket = Socket::CreateSocket(m_node, tid);
        InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), 12345);
        m_recvSocket->Bind(local);
        m_recvSocket->SetRecvCallback(MakeCallback(&AttackerApp::RecvDao, this));
        
        NS_LOG_WARN("ATTACKER (Node " << m_node->GetId() << ") started listening at t=" 
                    << Simulator::Now().GetSeconds());
        
        Simulator::Schedule(m_start, &AttackerApp::Replay, this);
      }
      
      void StopApplication() override { 
        if (m_recvSocket) m_recvSocket->Close(); 
      }
      
      uint32_t GetReplayCount() const { return m_replayCount; }
      uint32_t GetCaptureCount() const { return m_captureCount; }
    
    private:
      void RecvDao(Ptr<Socket> sock) {
        Address from; 
        Ptr<Packet> p = sock->RecvFrom(from);
        InetSocketAddress addr = InetSocketAddress::ConvertFrom(from);
        Ipv4Address src = addr.GetIpv4();
        
        // Only capture from source node (10.1.1.1), not from self
        std::ostringstream oss; oss << src;
        if (oss.str() == "10.1.1.1") {  // Only capture from source
          std::vector<uint8_t> buf(p->GetSize()); 
          p->CopyData(buf.data(), buf.size());
          m_last = buf;
          m_captureCount++;
          NS_LOG_WARN("ATTACKER (Node " << m_node->GetId() << ") CAPTURED DAO #" << m_captureCount
                      << " len=" << buf.size()
                      << " seq=" << (buf.empty() ? 0 : (unsigned)buf[0])
                      << " from " << oss.str()
                      << " at t=" << Simulator::Now().GetSeconds());
        }
      }
      
      void Replay() {
        if (m_last.empty()) { 
          NS_LOG_INFO("Attacker waiting for DAO to capture... t=" << Simulator::Now().GetSeconds());
          Simulator::Schedule(Seconds(0.5), &AttackerApp::Replay, this); 
          return; 
        }
        
        std::vector<uint8_t> msg = m_last;
        
        // perturb: flip bits to try evading detection (optional)
        if (m_perturb && msg.size() > 1) {
          msg[1 + (std::rand() % (msg.size()-1))] ^= (std::rand() & 0x3);
        }
        
        // Create NEW socket for each send (clean approach)
        Ptr<Socket> tx = Socket::CreateSocket(m_node, UdpSocketFactory::GetTypeId());
        tx->SetAllowBroadcast(true);
        InetSocketAddress dst = InetSocketAddress(Ipv4Address("255.255.255.255"), 12345);
        tx->Connect(dst);
        Ptr<Packet> pkt = Create<Packet>(msg.data(), msg.size());
        tx->Send(pkt);
        tx->Close();
        
        m_replayCount++;
        NS_LOG_WARN("ATTACKER sent REPLAY #" << m_replayCount << " (seq=" << (unsigned)msg[0] 
                    << ", hash=" << Crc16(msg.data(), msg.size())
                    << ") at t=" << Simulator::Now().GetSeconds());
        
        Simulator::Schedule(Seconds(1.0 / m_rate), &AttackerApp::Replay, this);
      }
    
      Ptr<Node> m_node;
      Ptr<Socket> m_recvSocket;  // Separate socket for receiving
      std::vector<uint8_t> m_last;
      double m_rate;
      Time m_start;
      bool m_perturb;
      uint32_t m_replayCount;
      uint32_t m_captureCount;
    };
 
 // ===================================================
 // main()
 // ===================================================
 int
 main(int argc, char *argv[])
 {
   uint32_t nNodes = 12;
   double spacing = 15.0;
   uint32_t gridWidth = 4;
   double simTime = 40.0;
   bool deterministicRoot = true;
   bool randomizeAttacker = false;
   bool disableRootProtection = false;  // CHANGED: Enable protection by default
   double attackerRate = 10.0;
   double attackStart = 8.0;
 
   CommandLine cmd;
   cmd.AddValue("nNodes", "Number of nodes", nNodes);
   cmd.AddValue("spacing", "Grid spacing (m)", spacing);
   cmd.AddValue("gridWidth", "Nodes per row", gridWidth);
   cmd.AddValue("simTime", "Simulation time", simTime);
   cmd.AddValue("deterministicRoot", "Fixed DAO payloads (true/false)", deterministicRoot);
   cmd.AddValue("randomizeAttacker", "Replay with small changes", randomizeAttacker);
   cmd.AddValue("disableRootProtection", "Disable root protection", disableRootProtection);
   cmd.AddValue("attackerRate", "Replay rate", attackerRate);
   cmd.AddValue("attackStart", "Replay start time", attackStart);
   cmd.Parse(argc, argv);
 
   std::srand((unsigned)time(nullptr));
   LogComponentEnable("RplDaoReplayDemo", LOG_LEVEL_WARN);  // Changed to WARN to see attacks
 
   NodeContainer nodes;
   nodes.Create(nNodes);

   std::cout << "\nSIMULATION PARAMETERS \n";
   std::cout << "Nodes: " << nNodes << "\n";
   std::cout << "Grid spacing: " << spacing << "m\n";
   std::cout << "Grid width: " << gridWidth << "\n";
   std::cout << "Simulation time: " << simTime << "s\n";
   std::cout << "Root protection: " << (disableRootProtection ? "DISABLED" : "ENABLED") << "\n";
   std::cout << "Attack start: " << attackStart << "s\n";
   std::cout << "Attack rate: " << attackerRate << " per sec\n";
   std::cout << "Deterministic payloads: " << (deterministicRoot ? "YES" : "NO") << "\n";
   std::cout << "Attacker perturbation: " << (randomizeAttacker ? "YES" : "NO") << "\n";
 
   // WiFi setup with increased transmission power
   YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
   YansWifiPhyHelper phy;
   phy.SetChannel(channel.Create());
   phy.Set("TxPowerStart", DoubleValue(23.0));  // Increased power
   phy.Set("TxPowerEnd", DoubleValue(23.0));
   WifiHelper wifi;
   wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                "DataMode", StringValue("OfdmRate6Mbps"),
                                "ControlMode", StringValue("OfdmRate6Mbps"));
   WifiMacHelper mac;
   mac.SetType("ns3::AdhocWifiMac");
   NetDeviceContainer devs = wifi.Install(phy, mac, nodes);
 
   // Mobility setup (static grid)
   MobilityHelper mobility;
   mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                 "MinX", DoubleValue(0.0),
                                 "MinY", DoubleValue(0.0),
                                 "DeltaX", DoubleValue(spacing),
                                 "DeltaY", DoubleValue(spacing),
                                 "GridWidth", UintegerValue(gridWidth),
                                 "LayoutType", StringValue("RowFirst"));
   mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
   mobility.Install(nodes);
 
   // IP stack
   InternetStackHelper internet;
   internet.Install(nodes);
   Ipv4AddressHelper ipv4;
   ipv4.SetBase("10.1.1.0", "255.255.255.0");
   Ipv4InterfaceContainer ifs = ipv4.Assign(devs);
 
   // DRM setup: each node gets one
   std::vector<Ptr<DrmComponent>> drm(nNodes);
   uint32_t attackerNodeId = 1;
   for (uint32_t i = 0; i < nNodes; ++i) {
    if (i == attackerNodeId) {
      drm[i] = nullptr;  // Attacker has no DRM
      continue;
    }
    Ptr<DrmComponent> c = CreateObject<DrmComponent>(nodes.Get(i));
    c->Setup(nodes.Get(i)->GetObject<Ipv4>());
    c->SetDisableRootProtection(disableRootProtection);
    drm[i] = c;
  }
 
   // DAO source (node 0)
   Ptr<DaoSourceApp> source = CreateObject<DaoSourceApp>();
   source->Setup(drm[0], Seconds(3.0), deterministicRoot);  // Changed to 3 seconds for faster testing
   nodes.Get(0)->AddApplication(source);
   source->SetStartTime(Seconds(1.0));
   source->SetStopTime(Seconds(simTime));
 
   // Attacker (node 1 - next to source!)
//    uint32_t attackerNodeId = 1;  // CRITICAL: Changed from nNodes-1 to 1
   Ptr<AttackerApp> attacker = CreateObject<AttackerApp>();
   attacker->Setup(nodes.Get(attackerNodeId), attackerRate, Seconds(attackStart), randomizeAttacker);
   nodes.Get(attackerNodeId)->AddApplication(attacker);
   attacker->SetStartTime(Seconds(0.5));
   attacker->SetStopTime(Seconds(simTime));
 
   std::cout << "Source node: 0 (IP: " << ifs.GetAddress(0) << ")\n";
   std::cout << "Attacker node: " << attackerNodeId << " (IP: " << ifs.GetAddress(attackerNodeId) << ")\n\n";

   Simulator::Stop(Seconds(simTime));
   Simulator::Run();
 
   // Aggregate metrics
   uint32_t totalControl = 0, totalDropped = 0;
   for (auto &d : drm) {
    if(d){
     totalControl += d->GetControlDaoCount();
     totalDropped += d->GetDroppedDaoCount();
        }    }
 
   uint32_t totalMitigationDrops = 0;
   for (auto &d : drm) {
    if(d){
     totalMitigationDrops += d->GetDroppedDueToMitigation();
    }
   }
 
   std::cout << "\nSIMULATION COMPLETE\n";
   std::cout << "Attacker sent " << attacker->GetReplayCount() << " replay packets\n";
   std::cout << "Total DAOs sent by source: " << drm[0]->GetControlDaoCount() << "\n";
   std::cout << "Total DAOs dropped (all nodes): " << totalDropped << "\n";
   std::cout << "DAOs dropped due to mitigation: " << totalMitigationDrops << "\n";
   std::cout << "Attack rate: " << attackerRate << " per sec, started at " << attackStart << "s\n";
 
   uint32_t totalSuspicious = 0;
   uint32_t totalBlacklists = 0;
   uint32_t totalReceivedDaos = 0;
   Time earliestDetection = Seconds(-1);
 
   for (auto &d : drm) {
    if(!d) continue;
     totalSuspicious += d->GetSuspiciousEvents();
     totalBlacklists += d->GetBlacklistCount();
     totalReceivedDaos += d->GetTotalReceived();
 
     Time t = d->GetFirstBlacklistTime();
     if (t != Seconds(-1)) {
       if (earliestDetection == Seconds(-1) || t < earliestDetection)
         earliestDetection = t;
     }
   }
 
   std::cout << "Total DAOs received (all nodes): " << totalReceivedDaos << "\n";
   std::cout << "Total suspicious events: " << totalSuspicious << "\n";
   std::cout << "Total blacklist events: " << totalBlacklists << "\n";
 
   if (earliestDetection != Seconds(-1))
     std::cout << "Detection time (first blacklist): " << earliestDetection.GetSeconds() << "s\n";
   else
     std::cout << "Detection time: NONE (no node blacklisted attacker)\n";
 
     std::cout << "\nPER-NODE DETECTION SUMMARY\n";
     for (uint32_t i = 0; i < nNodes; ++i) {
       if (i == attackerNodeId) {
         std::cout << "Node " << i << " (" << ifs.GetAddress(i) << "): ATTACKER NODE (no DRM)\n";
         continue;
       }
       
       std::ostringstream oss;
       oss << ifs.GetAddress(i);
       std::string nodeIp = oss.str();
       
       uint32_t rcvd = drm[i]->GetTotalReceived();
       uint32_t dropped = drm[i]->GetDroppedDaoCount();
       uint32_t susp = drm[i]->GetSuspiciousEvents();
       uint32_t bl = drm[i]->GetBlacklistCount();
       Time firstBl = drm[i]->GetFirstBlacklistTime();
       
       std::cout << "Node " << i << " (" << nodeIp << "): "
                 << "Received=" << rcvd 
                 << ", Dropped=" << dropped
                 << ", Suspicious=" << susp
                 << ", Blacklists=" << bl;
       
       if (firstBl != Seconds(-1)) {
           std::cout << ", FirstBL=" << firstBl.GetSeconds() << "s";
       }
       std::cout << "\n";
     }

   std::cout << "\nATTACKER STATISTICS \n";
std::cout << "DAOs captured: " << attacker->GetCaptureCount() << "\n";
std::cout << "Replays sent: " << attacker->GetReplayCount() << "\n";
 
   Simulator::Destroy();
   return 0;
 }
