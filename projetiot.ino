#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <lwip/etharp.h>
#include <ESP8266HTTPClient.h>

extern "C" {
  #include "user_interface.h"
}

// ==================== CONFIGURATION ====================
#define SSID "Tunisie_Telecom-2.4G-2057"
#define PASS "W9793bb32b"
#define PC_IP "192.168.1.249"
#define PC_PORT 5000

#define MAX_DEVICES 30
#define ARP_PING_DELAY 8
#define ARP_WAIT_TIME 2500
#define PORT_SCAN_TIMEOUT 40
#define SCAN_PASSES 3
#define MAX_ATTACKERS 10
#define HISTORY_SIZE 20

// ==================== SERVEUR WEB ====================
ESP8266WebServer server(80);

// ==================== STRUCTURES ====================
struct Device {
  uint8_t ip;
  uint8_t mac[6];
  uint8_t port;
  char type;
  uint16_t openPorts[10];
  uint8_t openPortCount;
  unsigned long lastSeen;
  uint16_t scanAttempts;
};

struct ARPCache {
  uint8_t ip;
  uint8_t mac[6];
  unsigned long lastSeen;
  bool active;
};

struct AttackerProfile {
  uint8_t mac[6];
  unsigned long deauthSent;
  unsigned long probesSent;
  unsigned long eapolSent;
  unsigned long arpSent;
  unsigned long beaconsSent;
  unsigned long lastSeen;
  bool suspicious;
};

struct FrameHistory {
  uint16_t seqNum;
  uint8_t srcMAC[6];
  unsigned long timestamp;
  bool wasRetry;
};

typedef struct {
  signed rssi:8;
  unsigned rate:4;
  unsigned is_group:1;
  unsigned sig_mode:2;
  unsigned legacy_length:12;
  unsigned damatch0:1;
  unsigned damatch1:1;
  unsigned bssidmatch0:1;
  unsigned bssidmatch1:1;
  unsigned MCS:7;
  unsigned CWB:1;
  unsigned HT_length:16;
  unsigned Smoothing:1;
  unsigned Not_Sounding:1;
  unsigned Aggregation:1;
  unsigned STBC:2;
  unsigned FEC_CODING:1;
  unsigned SGI:1;
  unsigned rxend_state:8;
  unsigned ampdu_cnt:8;
  unsigned channel:4;
} RxControl;

typedef struct {
  RxControl rx_ctrl;
  uint8_t buf[36];
  uint16_t cnt;
  uint8_t packet[0];
} SnifferPacket;

// ==================== VARIABLES GLOBALES ====================
Device devices[MAX_DEVICES];
ARPCache arpCache[MAX_DEVICES];
AttackerProfile attackers[MAX_ATTACKERS];
FrameHistory frameHistory[HISTORY_SIZE];

uint8_t deviceCount = 0;
uint8_t cacheSize = 0;
uint8_t attackerCount = 0;
uint8_t historyIndex = 0;

bool scanning = false;
bool isSniffing = false;
unsigned long scanStartTime = 0;
unsigned long snifferStartTime = 0;

unsigned long packetCount[256] = {0};
unsigned long totalPacketsCaptured = 0;

unsigned long deauthFrames = 0;
unsigned long disassocFrames = 0;
unsigned long authFrames = 0;
unsigned long beaconFrames = 0;
unsigned long probeRequests = 0;
unsigned long probeResponses = 0;
unsigned long eapolFrames = 0;
unsigned long arpRequests = 0;
unsigned long sequentialDeauth = 0;
unsigned long broadcastDeauth = 0;
unsigned long duplicateFrames = 0;
unsigned long fragmentedFrames = 0;
unsigned long wpsProbes = 0;
unsigned long eapStartFrames = 0;
unsigned long managementFrames = 0;
unsigned long dataFrames = 0;
unsigned long controlFrames = 0;

unsigned long lastDeauthTime = 0;
uint8_t lastDeauthSrcMAC[6] = {0};

// ==================== FONCTIONS HELPER ====================
void ICACHE_RAM_ATTR trackAttacker(uint8_t *mac, uint8_t attackType) {
  for (uint8_t i = 0; i < attackerCount; i++) {
    if (memcmp(attackers[i].mac, mac, 6) == 0) {
      switch (attackType) {
        case 0: attackers[i].deauthSent++; break;
        case 1: attackers[i].probesSent++; break;
        case 2: attackers[i].eapolSent++; break;
        case 3: attackers[i].arpSent++; break;
        case 4: attackers[i].beaconsSent++; break;
      }
      attackers[i].lastSeen = millis();
      
      if (attackers[i].deauthSent > 50 || attackers[i].probesSent > 200 ||
          attackers[i].eapolSent > 20 || attackers[i].arpSent > 100 ||
          attackers[i].beaconsSent > 500) {
        attackers[i].suspicious = true;
      }
      return;
    }
  }
  
  if (attackerCount < MAX_ATTACKERS) {
    memcpy(attackers[attackerCount].mac, mac, 6);
    attackers[attackerCount].deauthSent = (attackType == 0) ? 1 : 0;
    attackers[attackerCount].probesSent = (attackType == 1) ? 1 : 0;
    attackers[attackerCount].eapolSent = (attackType == 2) ? 1 : 0;
    attackers[attackerCount].arpSent = (attackType == 3) ? 1 : 0;
    attackers[attackerCount].beaconsSent = (attackType == 4) ? 1 : 0;
    attackers[attackerCount].lastSeen = millis();
    attackers[attackerCount].suspicious = false;
    attackerCount++;
  }
}

bool ICACHE_RAM_ATTR isDuplicateFrame(uint16_t seqNum, uint8_t *srcMAC, bool isRetry) {
  for (uint8_t i = 0; i < HISTORY_SIZE; i++) {
    if (frameHistory[i].seqNum == seqNum && 
        memcmp(frameHistory[i].srcMAC, srcMAC, 6) == 0) {
      if (millis() - frameHistory[i].timestamp < 1000) {
        if (isRetry && frameHistory[i].wasRetry) return false;
        if (!isRetry && !frameHistory[i].wasRetry) return true;
        return true;
      }
    }
  }
  
  frameHistory[historyIndex].seqNum = seqNum;
  memcpy(frameHistory[historyIndex].srcMAC, srcMAC, 6);
  frameHistory[historyIndex].timestamp = millis();
  frameHistory[historyIndex].wasRetry = isRetry;
  historyIndex = (historyIndex + 1) % HISTORY_SIZE;
  
  return false;
}

// ==================== CALLBACK SNIFFER ====================
void ICACHE_RAM_ATTR packetSnifferCallback(uint8_t *buffer, uint16_t length) {
  if (!isSniffing || length < 24) return;
  
  SnifferPacket *snifferPacket = (SnifferPacket*) buffer;
  uint8_t *packet = snifferPacket->packet;
  
  totalPacketsCaptured++;
  
  uint16_t frameControl = ((uint16_t)packet[1] << 8) | packet[0];
  uint8_t frameType = (frameControl >> 2) & 0x03;
  uint8_t frameSubtype = (frameControl >> 4) & 0x0F;
  bool toDS = (frameControl >> 8) & 0x01;
  bool fromDS = (frameControl >> 9) & 0x01;
  bool moreFrag = (frameControl >> 10) & 0x01;
  bool retry = (frameControl >> 11) & 0x01;
  
  uint16_t seqCtrl = ((uint16_t)packet[23] << 8) | packet[22];
  uint16_t seqNum = seqCtrl >> 4;
  uint8_t fragNum = seqCtrl & 0x0F;
  
  uint8_t destMAC[6], srcMAC[6], bssid[6];
  
  if (frameType == 0) {
    managementFrames++;
    memcpy(destMAC, &packet[4], 6);
    memcpy(srcMAC, &packet[10], 6);
    memcpy(bssid, &packet[16], 6);
    
    if (isDuplicateFrame(seqNum, srcMAC, retry)) duplicateFrames++;
    if (moreFrag || fragNum > 0) fragmentedFrames++;
    
    switch (frameSubtype) {
      case 0x0B:
        authFrames++;
        if (authFrames > 100) trackAttacker(srcMAC, 0);
        break;
        
      case 0x0C: {
        deauthFrames++;
        trackAttacker(srcMAC, 0);
        if (destMAC[0] == 0xFF && destMAC[1] == 0xFF) broadcastDeauth++;
        unsigned long now = millis();
        if (memcmp(srcMAC, lastDeauthSrcMAC, 6) == 0 && now - lastDeauthTime < 100) {
          sequentialDeauth++;
        }
        lastDeauthTime = now;
        memcpy(lastDeauthSrcMAC, srcMAC, 6);
        break;
      }
        
      case 0x0A:
        disassocFrames++;
        trackAttacker(srcMAC, 0);
        break;
        
      case 0x08:
        beaconFrames++;
        if (beaconFrames > 500) trackAttacker(srcMAC, 4);
        break;
        
      case 0x04: {
        probeRequests++;
        uint8_t offset = 24;
        while (offset + 2 < length) {
          uint8_t ieType = packet[offset];
          uint8_t ieLen = packet[offset + 1];
          if (offset + 2 + ieLen > length) break;
          
          if (ieType == 0xDD && ieLen >= 4) {
            if (packet[offset + 2] == 0x00 && packet[offset + 3] == 0x50 && 
                packet[offset + 4] == 0xF2 && packet[offset + 5] == 0x04) {
              wpsProbes++;
              trackAttacker(srcMAC, 1);
            }
          }
          offset += 2 + ieLen;
        }
        if (probeRequests > 300) trackAttacker(srcMAC, 1);
        break;
      }
        
      case 0x05:
        probeResponses++;
        break;
    }
  }
  else if (frameType == 2) {
    dataFrames++;
    
    if (!toDS && !fromDS) {
      memcpy(destMAC, &packet[4], 6);
      memcpy(srcMAC, &packet[10], 6);
      memcpy(bssid, &packet[16], 6);
    } else if (toDS && !fromDS) {
      memcpy(bssid, &packet[4], 6);
      memcpy(srcMAC, &packet[10], 6);
      memcpy(destMAC, &packet[16], 6);
    } else if (!toDS && fromDS) {
      memcpy(destMAC, &packet[4], 6);
      memcpy(bssid, &packet[10], 6);
      memcpy(srcMAC, &packet[16], 6);
    }
    
    packetCount[srcMAC[5]]++;
    if (isDuplicateFrame(seqNum, srcMAC, retry)) duplicateFrames++;
    
    uint16_t offset = 24;
    if (frameSubtype == 0x08) offset += 2;
    
    if (length > offset + 8) {
      if (packet[offset] == 0xAA && packet[offset+1] == 0xAA && 
          packet[offset+2] == 0x03 && packet[offset+6] == 0x88 && 
          packet[offset+7] == 0x8E) {
        eapolFrames++;
        trackAttacker(srcMAC, 2);
        uint8_t *eapol = &packet[offset + 8];
        if (length > offset + 12 && eapol[1] == 0) eapStartFrames++;
      }
      else if (packet[offset] == 0xAA && packet[offset+1] == 0xAA && 
               packet[offset+2] == 0x03 && packet[offset+6] == 0x08 && 
               packet[offset+7] == 0x06) {
        arpRequests++;
        trackAttacker(srcMAC, 3);
      }
    }
  }
  else if (frameType == 1) {
    controlFrames++;
  }
}

// ==================== CACHE ARP ====================
void updateARPCache(uint8_t ip, uint8_t* mac) {
  for (uint8_t i = 0; i < cacheSize; i++) {
    if (arpCache[i].ip == ip) {
      memcpy(arpCache[i].mac, mac, 6);
      arpCache[i].lastSeen = millis();
      arpCache[i].active = true;
      return;
    }
  }
  
  if (cacheSize < MAX_DEVICES) {
    arpCache[cacheSize].ip = ip;
    memcpy(arpCache[cacheSize].mac, mac, 6);
    arpCache[cacheSize].lastSeen = millis();
    arpCache[cacheSize].active = true;
    cacheSize++;
  }
}

void cleanupARPCache() {
  uint8_t newSize = 0;
  unsigned long now = millis();
  
  for (uint8_t i = 0; i < cacheSize; i++) {
    if (arpCache[i].active && (now - arpCache[i].lastSeen) < 300000) {
      if (i != newSize) arpCache[newSize] = arpCache[i];
      newSize++;
    }
  }
  cacheSize = newSize;
}

// ==================== ARP ====================
void arpPing(IPAddress ip) {
  ip4_addr_t ipaddr;
  IP4_ADDR(&ipaddr, ip[0], ip[1], ip[2], ip[3]);
  struct netif *netif = netif_default;
  if (netif != NULL) etharp_request(netif, &ipaddr);
}

bool getARPEntry(IPAddress ip, uint8_t* mac) {
  ip4_addr_t ipaddr;
  IP4_ADDR(&ipaddr, ip[0], ip[1], ip[2], ip[3]);
  
  struct eth_addr* ethAddr = NULL;
  ip4_addr_t* ipRet = NULL;
  struct netif* netif = NULL;
  
  for (int i = 0; i < ARP_TABLE_SIZE; i++) {
    if (etharp_get_entry(i, &ipRet, &netif, &ethAddr) != 0) {
      if (ipRet != NULL && ipRet->addr == ipaddr.addr) {
        if (ethAddr != NULL) {
          memcpy(mac, ethAddr->addr, 6);
          return true;
        }
      }
    }
  }
  return false;
}

// ==================== SCAN PORTS ====================
void scanPortsQuick(IPAddress ip, Device &device) {
  WiFiClient client;
  client.setTimeout(PORT_SCAN_TIMEOUT);
  device.openPortCount = 0;
  device.scanAttempts = 0;
  
  uint16_t ports[] = {80, 443, 22, 445, 3389, 8080};
  
  for (uint8_t i = 0; i < 6 && device.openPortCount < 10; i++) {
    device.scanAttempts++;
    if (client.connect(ip, ports[i])) {
      device.openPorts[device.openPortCount++] = ports[i];
      client.stop();
      delay(3);
    }
    yield();
  }
}

char detectDeviceType(IPAddress ip, uint8_t* mac, uint8_t &port) {
  WiFiClient client;
  client.setTimeout(PORT_SCAN_TIMEOUT);
  
  if (client.connect(ip, 80))   { client.stop(); port = 80;   return 'W'; }
  if (client.connect(ip, 443))  { client.stop(); port = 443;  return 'H'; }
  if (client.connect(ip, 8080)) { client.stop(); port = 8080; return 'W'; }
  if (client.connect(ip, 445))  { client.stop(); port = 445;  return 'S'; }
  if (client.connect(ip, 22))   { client.stop(); port = 22;   return 'L'; }
  if (client.connect(ip, 3389)) { client.stop(); port = 3389; return 'R'; }
  
  port = 0;
  return 'SmartPhone/TV';
}

// ==================== SCAN RÉSEAU ====================
void performScan() {
  if (scanning) return;
  
  scanning = true;
  deviceCount = 0;
  scanStartTime = millis();
  
  Serial.println("\n╔════════════════════════════════════╗");
  Serial.println("║  SCAN RÉSEAU v4.1 OPTIMISÉ        ║");
  Serial.println("╚════════════════════════════════════╝");
  
  IPAddress localIP = WiFi.localIP();
  uint8_t base[3] = {localIP[0], localIP[1], localIP[2]};
  
  Serial.printf("📍 %d.%d.%d.0/24 | 📡 %s | 💾 %d cache\n", 
                base[0], base[1], base[2], localIP.toString().c_str(), cacheSize);
  
  // Cache
  if (cacheSize > 0) {
    Serial.println("\n[1/4] 💾 Cache...");
    for (uint8_t i = 0; i < cacheSize; i++) {
      if (!arpCache[i].active) continue;
      IPAddress target(base[0], base[1], base[2], arpCache[i].ip);
      for (uint8_t r = 0; r < 3; r++) { arpPing(target); delay(10); }
      yield();
    }
    delay(1500);
  }
  
  // IPs prioritaires
  Serial.println("\n[2/4] 🚀 Prioritaires...");
  uint8_t priority[] = {1, 100, 249, 250, 251, 252, 253, 254};
  for (uint8_t i = 0; i < sizeof(priority); i++) {
    if (priority[i] == localIP[3]) continue;
    IPAddress target(base[0], base[1], base[2], priority[i]);
    for (uint8_t r = 0; r < 3; r++) { arpPing(target); delay(ARP_PING_DELAY); }
    yield();
  }
  delay(ARP_WAIT_TIME);
  
  // Scan complet
  Serial.println("\n[3/4] 📡 Scan...");
  for (uint8_t pass = 1; pass <= SCAN_PASSES; pass++) {
    for (uint8_t i = 1; i <= 254; i++) {
      if (i == localIP[3]) continue;
      arpPing(IPAddress(base[0], base[1], base[2], i));
      if (i % (pass == 1 ? 8 : 20) == 0) { delay(pass == 1 ? 10 : 20); yield(); }
    }
    if (pass < SCAN_PASSES) delay(pass == 1 ? 2000 : 3000);
  }
  
  // Lecture ARP
  Serial.println("\n[4/4] 📖 ARP + Ports...");
  delay(ARP_WAIT_TIME);
  
  for (uint8_t i = 1; i <= 254 && deviceCount < MAX_DEVICES; i++) {
    if (i == localIP[3]) continue;
    
    IPAddress target(base[0], base[1], base[2], i);
    uint8_t mac[6] = {0};
    
    if (getARPEntry(target, mac)) {
      bool exists = false;
      for (uint8_t j = 0; j < deviceCount; j++) {
        if (devices[j].ip == i || memcmp(devices[j].mac, mac, 6) == 0) {
          exists = true;
          devices[j].lastSeen = millis();
          break;
        }
      }
      
      if (!exists) {
        uint8_t port;
        char type = detectDeviceType(target, mac, port);
        
        devices[deviceCount].ip = i;
        memcpy(devices[deviceCount].mac, mac, 6);
        devices[deviceCount].port = port;
        devices[deviceCount].type = type;
        devices[deviceCount].lastSeen = millis();
        devices[deviceCount].openPortCount = 0;
        devices[deviceCount].scanAttempts = 0;
        
        scanPortsQuick(target, devices[deviceCount]);
        
        Serial.printf("   ✅ .%d | %02X:%02X:...:%02X | %c | %d ports\n",
                      i, mac[0], mac[1], mac[5], type, devices[deviceCount].openPortCount);
        
        updateARPCache(i, mac);
        deviceCount++;
      }
    }
    yield();
  }
  
  cleanupARPCache();
  
  unsigned long duration = millis() - scanStartTime;
  Serial.printf("\n✅ %d appareils en %lus | 💾 %d cache\n", deviceCount, duration/1000, cacheSize);
  
  scanning = false;
}

// ==================== SNIFFER ====================
void performPentestDetection() {
  Serial.println("\n╔════════════════════════════════════╗");
  Serial.println("║  SNIFFER PENTEST (20s)            ║");
  Serial.println("╚════════════════════════════════════╝");
  
  memset(packetCount, 0, sizeof(packetCount));
  memset(attackers, 0, sizeof(attackers));
  memset(frameHistory, 0, sizeof(frameHistory));
  
  totalPacketsCaptured = deauthFrames = disassocFrames = authFrames = 0;
  beaconFrames = probeRequests = probeResponses = eapolFrames = 0;
  arpRequests = sequentialDeauth = broadcastDeauth = duplicateFrames = 0;
  fragmentedFrames = wpsProbes = eapStartFrames = 0;
  managementFrames = dataFrames = controlFrames = 0;
  attackerCount = historyIndex = 0;
  
  Serial.println("⚠️  Disconnect...");
  delay(1000);
  
  wifi_set_opmode(STATION_MODE);
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(packetSnifferCallback);
  wifi_promiscuous_enable(1);
  
  isSniffing = true;
  snifferStartTime = millis();
  
  Serial.println("🔍 Capture...");
  
  while (millis() - snifferStartTime < 20000) {
    delay(100);
    if ((millis() - snifferStartTime) % 5000 < 150) {
      Serial.printf("📊 %lu pkt | Deauth:%lu | Probe:%lu | EAPOL:%lu | Dupl:%lu\n",
                    totalPacketsCaptured, deauthFrames, probeRequests, eapolFrames, duplicateFrames);
    }
  }
  
  isSniffing = false;
  wifi_promiscuous_enable(0);
  
  Serial.printf("\n✅ %lu paquets | Mgmt:%lu Data:%lu Ctrl:%lu\n",
                totalPacketsCaptured, managementFrames, dataFrames, controlFrames);
  
  bool threat = false;
  if (deauthFrames > 100) { Serial.println("🚨 AIREPLAY DEAUTH!"); threat = true; }
  if (beaconFrames > 1000) { Serial.println("🚨 MDK3 FLOOD!"); threat = true; }
  if (probeRequests > 500) { Serial.println("🚨 AIRODUMP SCAN!"); threat = true; }
  if (wpsProbes > 20) { Serial.println("🚨 WASH/REAVER!"); threat = true; }
  if (duplicateFrames > 1000) { Serial.println("🚨 REPLAY ATTACK!"); threat = true; }
  if (!threat) Serial.println("✅ Aucune menace");
  
  Serial.println("\n📡 Reconnexion...");
  WiFi.mode(WIFI_STA);
  WiFi.begin(SSID, PASS);
  
  uint8_t attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 20) {
    delay(500);
    Serial.print(".");
    attempts++;
  }
  Serial.println(WiFi.status() == WL_CONNECTED ? " ✅" : " ❌");
}

// ==================== JSON ====================
String buildJSON() {
  String json;
  json.reserve(4500);
  
  json = "{\"esp_ip\":\"" + WiFi.localIP().toString() + "\",";
  json += "\"scan_duration\":" + String(millis() - scanStartTime) + ",";
  json += "\"timestamp\":" + String(millis()) + ",";
  
  json += "\"ddos_detection\":{\"total_packets\":" + String(totalPacketsCaptured);
  json += ",\"packets_per_sec\":" + String(totalPacketsCaptured / 20);
  json += ",\"capture_duration\":20000,\"top_sources\":[";
  
  typedef struct { uint8_t idx; unsigned long cnt; } Src;
  Src top[10] = {0};
  
  for (int i = 0; i < 256; i++) {
    if (packetCount[i] > 0) {
      for (int j = 0; j < 10; j++) {
        if (packetCount[i] > top[j].cnt) {
          for (int k = 9; k > j; k--) top[k] = top[k-1];
          top[j].idx = i;
          top[j].cnt = packetCount[i];
          break;
        }
      }
    }
  }
  
  for (int i = 0; i < 10 && top[i].cnt > 0; i++) {
    if (i > 0) json += ",";
    json += "{\"mac_suffix\":" + String(top[i].idx) + ",\"packet_count\":" + String(top[i].cnt) + "}";
  }
  json += "]},";
  
  json += "\"wifi_pentest_detection\":{";
  json += "\"deauth_frames\":" + String(deauthFrames);
  json += ",\"disassoc_frames\":" + String(disassocFrames);
  json += ",\"auth_frames\":" + String(authFrames);
  json += ",\"beacon_frames\":" + String(beaconFrames);
  json += ",\"probe_requests\":" + String(probeRequests);
  json += ",\"eapol_frames\":" + String(eapolFrames);
  json += ",\"arp_requests\":" + String(arpRequests);
  json += ",\"sequential_deauth\":" + String(sequentialDeauth);
  json += ",\"broadcast_deauth\":" + String(broadcastDeauth);
  json += ",\"wps_probes\":" + String(wpsProbes);
  json += ",\"eap_start_frames\":" + String(eapStartFrames);
  json += ",\"duplicate_frames\":" + String(duplicateFrames);
  json += ",\"fragmented_frames\":" + String(fragmentedFrames);
  json += ",\"management_frames\":" + String(managementFrames);
  json += ",\"data_frames\":" + String(dataFrames);
  json += ",\"control_frames\":" + String(controlFrames);
  json += ",\"attackers\":[";
  
  for (uint8_t i = 0; i < attackerCount; i++) {
    if (i > 0) json += ",";
    json += "{\"mac\":\"";
    for (int j = 0; j < 6; j++) {
      if (attackers[i].mac[j] < 16) json += "0";
      json += String(attackers[i].mac[j], HEX);
      if (j < 5) json += ":";
    }
    json += "\",\"deauth\":" + String(attackers[i].deauthSent);
    json += ",\"probes\":" + String(attackers[i].probesSent);
    json += ",\"eapol\":" + String(attackers[i].eapolSent);
    json += ",\"arp\":" + String(attackers[i].arpSent);
    json += ",\"beacons\":" + String(attackers[i].beaconsSent);
    json += ",\"suspicious\":" + String(attackers[i].suspicious ? "true" : "false") + "}";
  }
  json += "]},\"devices\":[";
  
  for (uint8_t i = 0; i < deviceCount; i++) {
    if (i > 0) json += ",";
    json += "{\"ip\":\"" + String(WiFi.localIP()[0]) + "." + String(WiFi.localIP()[1]) + "." + 
            String(WiFi.localIP()[2]) + "." + String(devices[i].ip) + "\",\"mac\":\"";
    for (int j = 0; j < 6; j++) {
      if (devices[i].mac[j] < 16) json += "0";
      json += String(devices[i].mac[j], HEX);
      if (j < 5) json += ":";
    }
    json += "\",\"type\":\"" + String(devices[i].type) + "\",\"primary_port\":" + String(devices[i].port);
    json += ",\"open_ports\":[";
    for (uint8_t j = 0; j < devices[i].openPortCount; j++) {
      if (j > 0) json += ",";
      json += String(devices[i].openPorts[j]);
    }
    json += "],\"open_port_count\":" + String(devices[i].openPortCount);
    json += ",\"scan_attempts\":" + String(devices[i].scanAttempts);
    json += ",\"last_seen\":" + String(devices[i].lastSeen) + "}";
  }
  json += "]}";
  
  return json;
}

// ==================== ENVOI ====================
void sendScanToPC(String json) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("❌ WiFi KO!");
    return;
  }
  
  String url = "http://" + String(PC_IP) + ":" + String(PC_PORT) + "/scan";
  Serial.printf("\n📤 POST %s | %d dev | %lu pkt\n", url.c_str(), deviceCount, totalPacketsCaptured);
  
  HTTPClient http;
  WiFiClient client;
  
  http.begin(client, url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(15000);
  
  int code = http.POST(json);
  Serial.printf("📨 HTTP %d %s\n", code, code > 0 ? "✅" : "❌");
  
  if (code == HTTP_CODE_OK || code == HTTP_CODE_CREATED) {
    Serial.println("📥 " + http.getString());
  }
  
  http.end();
}

// ==================== HTML ====================
const char HTML_PAGE[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>ESP Pentest Detector v4.1</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#1a1a2e,#16213e,#0f3460,#533483);color:#fff;padding:20px;min-height:100vh}
.container{max-width:900px;margin:0 auto}
.header{text-align:center;margin-bottom:30px;padding:35px;background:linear-gradient(135deg,rgba(239,83,80,0.2),rgba(239,83,80,0.1));border-radius:15px;border:2px solid rgba(239,83,80,0.4);box-shadow:0 10px 40px rgba(0,0,0,0.5)}
h1{background:linear-gradient(135deg,#ef5350,#ff6f00,#ff1744);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-size:2.5em;font-weight:700;margin-bottom:15px}
.subtitle{color:#ffab91;font-size:1em;margin-bottom:20px}
.device-info{display:flex;justify-content:center;gap:10px;margin-top:15px;flex-wrap:wrap}
.info-badge{background:rgba(30,30,50,0.8);border:1px solid rgba(239,83,80,0.3);padding:8px 15px;border-radius:20px;font-size:0.85em;color:#ffccbc}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin-bottom:30px}
.stat{background:linear-gradient(135deg,rgba(30,30,50,0.95),rgba(20,20,40,0.9));padding:25px;border-radius:12px;border:1px solid rgba(239,83,80,0.3);text-align:center;transition:all 0.3s}
.stat:hover{transform:translateY(-8px);border-color:rgba(239,83,80,0.6);box-shadow:0 10px 30px rgba(239,83,80,0.3)}
.stat-num{font-size:3em;font-weight:800;color:#00e676;text-shadow:0 0 20px rgba(0,230,118,0.5);margin:15px 0;font-family:'SF Mono',monospace}
.stat-label{color:#b0bec5;font-size:0.9em;text-transform:uppercase;letter-spacing:2px;font-weight:600}
.btn{display:block;width:100%;padding:20px;border:none;border-radius:12px;font-size:1.2em;font-weight:700;cursor:pointer;text-transform:uppercase;letter-spacing:1.5px;transition:all 0.3s;margin-bottom:15px}
.btn:disabled{opacity:0.5;cursor:not-allowed}
.btn-dashboard{background:linear-gradient(135deg,#00e676,#00c853);color:#1a1a2e;box-shadow:0 4px 20px rgba(0,230,118,0.4)}
.btn-dashboard:hover{transform:translateY(-3px);box-shadow:0 8px 35px rgba(0,230,118,0.8)}
.btn-primary{background:linear-gradient(135deg,#ff1744,#f50057);color:#fff;box-shadow:0 4px 20px rgba(255,23,68,0.4)}
.btn-primary:hover{transform:translateY(-3px);box-shadow:0 8px 30px rgba(255,23,68,0.6)}
.info-card{background:linear-gradient(135deg,rgba(30,30,50,0.95),rgba(20,20,40,0.9));padding:25px;border-radius:12px;border:1px solid rgba(239,83,80,0.3);margin-bottom:20px}
.info-title{color:#ef5350;font-size:1.3em;font-weight:700;margin-bottom:15px}
.info-item{padding:12px 0;border-bottom:1px solid rgba(255,255,255,0.1);display:flex;justify-content:space-between}
.info-item:last-child{border-bottom:none}
.info-key{color:#b0bec5;font-weight:600}
.info-value{color:#ff5252;font-weight:700;font-family:'SF Mono',monospace}
@media(max-width:768px){.stats{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class='container'>
<div class='header'>
<h1>🛡️ ESP PENTEST DETECTOR</h1>
<div class='subtitle'>Détection WiFi automatique</div>
<div class='device-info'>
<span class='info-badge'>📡 {{IP}}</span>
<span class='info-badge'>📶 {{RSSI}} dBm</span>
<span class='info-badge'>🔄 Auto 60s</span>
</div>
</div>

<div class='stats'>
<div class='stat'>
<div class='stat-num'>{{DEVICES}}</div>
<div class='stat-label'>Appareils</div>
</div>
<div class='stat'>
<div class='stat-num'>{{PACKETS}}</div>
<div class='stat-label'>Paquets</div>
</div>
<div class='stat'>
<div class='stat-num'>{{CACHE}}</div>
<div class='stat-label'>Cache</div>
</div>
</div>

<button class='btn btn-dashboard' onclick="location.href='http://{{SERVER}}'">
 DASHBOARD COMPLET
</button>
<button class='btn btn-primary' onclick='scan()' id='btn'>
SCAN MANUEL
</button>

<div class='info-card'>
<div class='info-title'>ℹ️ Informations ESP8266</div>
<div class='info-item'><span class='info-key'>🌐 IP</span><span class='info-value'>{{IP}}</span></div>
<div class='info-item'><span class='info-key'>📍 Réseau</span><span class='info-value'>{{NETWORK}}.0/24</span></div>
<div class='info-item'><span class='info-key'>🖥️ Serveur</span><span class='info-value'>{{SERVER}}</span></div>
<div class='info-item'><span class='info-key'>⏱️ Scan</span><span class='info-value'>{{DURATION}}s</span></div>
</div>

<div class='info-card'>
<div class='info-title'>🎯 Détections disponibles</div>
<div class='info-item'><span class='info-key'> Scan ARP</span><span class='info-value'>Cache persistant</span></div>
<div class='info-item'><span class='info-key'>DDoS</span><span class='info-value'>Analyse trafic</span></div>
<div class='info-item'><span class='info-key'>Pentest</span><span class='info-value'>Aireplay/Wash/MDK3</span></div>
<div class='info-item'><span class='info-key'>Spoofing</span><span class='info-value'>ARP/MAC/MITM</span></div>
</div>
</div>

<script>
function scan(){
const b=document.getElementById('btn');
if(b.disabled)return;
b.disabled=true;
b.textContent='⏳ SCAN (50s)...';
fetch('/scan').then(()=>setTimeout(()=>location.reload(),50000)).catch(e=>{
alert('❌ '+e);
b.disabled=false;
b.textContent='SCAN MANUEL';
});
}
console.log('🛡️ ESP v4.1 | Auto-scan: 60s | Dashboard: http://{{SERVER}}');
</script>
</body>
</html>
)rawliteral";

String getHTML() {
  String html = FPSTR(HTML_PAGE);
  IPAddress ip = WiFi.localIP();
  String network = String(ip[0]) + "." + String(ip[1]) + "." + String(ip[2]);
  String server = String(PC_IP) + ":" + String(PC_PORT);
  
  html.replace("{{DEVICES}}", String(deviceCount));
  html.replace("{{PACKETS}}", String(totalPacketsCaptured));
  html.replace("{{CACHE}}", String(cacheSize));
  html.replace("{{IP}}", ip.toString());
  html.replace("{{NETWORK}}", network);
  html.replace("{{SERVER}}", server);
  html.replace("{{RSSI}}", String(WiFi.RSSI()));
  html.replace("{{DURATION}}", String((millis() - scanStartTime) / 1000));
  
  return html;
}

// ==================== HANDLERS ====================
void handleRoot() { 
  server.send(200, "text/html", getHTML()); 
}

void handleScan() {
  server.send(200, "text/plain", "Scan démarré");
  performScan();
  performPentestDetection();
  if (WiFi.status() == WL_CONNECTED) {
    sendScanToPC(buildJSON());
  }
}

// ==================== SETUP ====================
void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println("\n╔════════════════════════════════╗");
  Serial.println("║  ESP PENTEST DETECTOR v4.1     ║");
  Serial.println("║  Optimisé + Filtre retry       ║");
  Serial.println("╚════════════════════════════════╝\n");
  
  WiFi.mode(WIFI_STA);
  WiFi.begin(SSID, PASS);
  
  Serial.print("📡 Connexion");
  uint8_t tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 30) {
    delay(500);
    Serial.print(".");
    tries++;
  }
  Serial.println();
  
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("✅ WiFi OK!");
    Serial.printf("📍 IP: %s\n", WiFi.localIP().toString().c_str());
    Serial.printf("📶 Signal: %d dBm\n", WiFi.RSSI());
    Serial.printf("🖥️ Serveur: %s:%d\n\n", PC_IP, PC_PORT);
    
    server.on("/", handleRoot);
    server.on("/scan", handleScan);
    server.begin();
    
    Serial.println("🌐 Serveur actif");
    Serial.println("🔗 http://" + WiFi.localIP().toString() + "\n");
    
    delay(2000);
    
    Serial.println("🚀 Scan initial...\n");
    performScan();
    performPentestDetection();
    
    if (WiFi.status() == WL_CONNECTED) {
      sendScanToPC(buildJSON());
    }
  } else {
    Serial.println("❌ WiFi KO!");
  }
}

// ==================== LOOP ====================
void loop() {
  server.handleClient();
  yield();
  
  static unsigned long lastScan = 0;
  
  if (!scanning && !isSniffing && millis() - lastScan > 60000) {
    lastScan = millis();
    Serial.println("\n⏰ Scan auto...");
    performScan();
    performPentestDetection();
    if (WiFi.status() == WL_CONNECTED) {
      sendScanToPC(buildJSON());
    } else {
      Serial.println("⚠️ Reconnect...");
      WiFi.reconnect();
    }
  }
}