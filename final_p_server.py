from flask import Flask, request, jsonify, render_template_string
from datetime import datetime, timedelta
from collections import defaultdict, deque

app = Flask(__name__)

# ==================== STOCKAGE DES DONNÉES ====================
scan_history = []
devices_database = {}
alerts = []
current_alerts = []
attack_stats = defaultdict(int)

alert_history = deque(maxlen=50)
device_count_history = deque(maxlen=50)

last_ddos_stats = {
    'total_packets': 0,
    'packets_per_sec': 0,
    'capture_time': 'N/A'
}

current_stats = {
    'total_devices': 0,
    'alert_count': 0,
    'network_packets': 0,
    'packets_per_sec': 0,
    'ddos_count': 0,
    'backdoor_count': 0,  # ✅ CHANGÉ : nmap_count → backdoor_count
    'last_scan': 'Aucun',
    'status': 'SECURE'
}

TRUSTED_IPS = ['192.168.1.179', '192.168.1.1']
TRUSTED_MACS = []
WHITELIST = []
BLACKLIST = []
MAX_HISTORY = 100
ALERT_EXPIRATION_MINUTES = 2  # ✅  2 minutes

# ==================== CLASSE DE DÉTECTION ====================
class AttackDetector:
    def __init__(self):
        self.previous_scan = {}
        self.mac_ip_history = defaultdict(list)
        self.ip_mac_history = defaultdict(list)
        self.gateway_mac = None
        
    def analyze(self, scan_data):
        threats = []
        current_devices = scan_data.get('devices', [])
        esp_ip = scan_data.get('esp_ip', '')
        network = '.'.join(esp_ip.split('.')[:3])
        gateway_ip = f"{network}.1"
        
        for device in current_devices:
            ip = device.get('ip', '')
            mac = device.get('mac', '').upper()
            is_trusted = ip in TRUSTED_IPS or mac in TRUSTED_MACS
            open_ports = device.get('open_ports', [])
            open_port_count = device.get('open_port_count', 0)
            suspicious_ports = device.get('suspicious_ports', [])  # ✅ NOUVEAU
            
            threats.extend(self.detect_arp_spoofing(ip, mac))
            threats.extend(self.detect_mac_spoofing(ip, mac))
            if ip == gateway_ip:
                threats.extend(self.detect_gateway_spoofing(mac))
            threats.extend(self.detect_unauthorized_device(mac))
            threats.extend(self.detect_blacklisted_device(mac, ip))
            
            # ✅ NOUVEAU : Détection des ports suspects (PRIORITAIRE)
            if suspicious_ports and len(suspicious_ports) > 0:
                threats.extend(self.detect_suspicious_ports(ip, mac, suspicious_ports))
            
            self.update_history(ip, mac, open_ports)
        
        threats.extend(self.detect_disappeared_devices(current_devices))
        current_devices_untrusted = [d for d in current_devices if d.get('ip') not in TRUSTED_IPS and d.get('mac', '').upper() not in TRUSTED_MACS]
        threats.extend(self.detect_distributed_ddos(current_devices_untrusted))
        self.previous_scan = {d['ip']: d for d in current_devices}
        return threats
    
    # ✅ NOUVELLE FONCTION : Détection des ports suspects
    def detect_suspicious_ports(self, ip, mac, suspicious_ports):
        """
        Détecte les ports suspects (backdoors, trojans, services vulnérables).
        Cette fonction analyse UNIQUEMENT les ports de la liste suspicious_ports envoyée par l'ESP.
        """
        threats = []
        
        if not suspicious_ports or len(suspicious_ports) == 0:
            return threats
        
        # ✅ DICTIONNAIRE DES PORTS SUSPECTS AVEC CATÉGORIES
        SUSPICIOUS_PORT_DB = {
            # === BACKDOORS & TROJANS (CRITICAL) ===
            31337: {"name": "Back Orifice", "severity": "CRITICAL", "category": "backdoor"},
            12345: {"name": "NetBus", "severity": "CRITICAL", "category": "backdoor"},
            27374: {"name": "SubSeven", "severity": "CRITICAL", "category": "trojan"},
            54321: {"name": "Back Orifice 2000", "severity": "CRITICAL", "category": "backdoor"},
            6666: {"name": "Beast Trojan", "severity": "CRITICAL", "category": "trojan"},
            1243: {"name": "SubSeven", "severity": "CRITICAL", "category": "trojan"},
            6667: {"name": "IRC (Botnet)", "severity": "CRITICAL", "category": "botnet"},
            
            # === OUTILS DE HACK (HIGH) ===
            4444: {"name": "Metasploit (default)", "severity": "HIGH", "category": "exploit"},
            5555: {"name": "Android ADB / HP Data Protector", "severity": "HIGH", "category": "exploit"},
            8888: {"name": "Alt HTTP (suspect)", "severity": "HIGH", "category": "suspicious"},
            9999: {"name": "Hidden Port", "severity": "HIGH", "category": "suspicious"},
            1337: {"name": "Elite/Leet", "severity": "MEDIUM", "category": "suspicious"},
            
            # === SERVICES VULNÉRABLES (MEDIUM-HIGH) ===
            2222: {"name": "SSH alternatif (backdoor?)", "severity": "MEDIUM", "category": "suspicious"},
            10000: {"name": "Webmin (souvent exploité)", "severity": "HIGH", "category": "vulnerable"},
            
            # === BASE DE DONNÉES EXPOSÉES (HIGH) ===
            3306: {"name": "MySQL (exposition dangereuse)", "severity": "HIGH", "category": "database"},
            5432: {"name": "PostgreSQL (exposition dangereuse)", "severity": "HIGH", "category": "database"},
            1433: {"name": "MS SQL Server (exposition dangereuse)", "severity": "HIGH", "category": "database"}
        }
        
        # ✅ WHITELIST : IPs de confiance (ne jamais alerter)
        if ip in TRUSTED_IPS:
            return threats
        
        # ✅ Analyser les ports suspects détectés
        detected_critical = []  # Backdoors/Trojans
        detected_high = []      # Exploits/DB exposées
        detected_medium = []    # Services suspects
        
        for port in suspicious_ports:
            if port in SUSPICIOUS_PORT_DB:
                port_info = SUSPICIOUS_PORT_DB[port]
                
                if port_info['severity'] == 'CRITICAL':
                    detected_critical.append({
                        'port': port,
                        'name': port_info['name'],
                        'category': port_info['category']
                    })
                elif port_info['severity'] == 'HIGH':
                    detected_high.append({
                        'port': port,
                        'name': port_info['name'],
                        'category': port_info['category']
                    })
                else:
                    detected_medium.append({
                        'port': port,
                        'name': port_info['name'],
                        'category': port_info['category']
                    })
        
        # ========== ALERTE CRITIQUE : BACKDOOR/TROJAN ==========
        if detected_critical:
            port_details = [f"Port {p['port']} ({p['name']})" for p in detected_critical]
            
            threats.append({
                'type': 'BACKDOOR_TROJAN',
                'severity': 'CRITICAL',
                'ip': ip,
                'mac': mac,
                'description': f'🚨 BACKDOOR/TROJAN détecté sur {ip} !',
                'details': f'Menaces critiques : {" | ".join(port_details)}',
                'recommendation': '⚠️ ISOLER CET APPAREIL IMMÉDIATEMENT ! Déconnectez-le du réseau et lancez un scan antivirus complet.'
            })
            
            print(f"   🚨 CRITIQUE : {ip} - Backdoor/Trojan détecté : {port_details}")
        
        # ========== ALERTE HAUTE : EXPLOIT/DB EXPOSÉES ==========
        elif detected_high:
            port_details = [f"Port {p['port']} ({p['name']})" for p in detected_high]
            
            threats.append({
                'type': 'VULNERABLE_SERVICE',
                'severity': 'HIGH',
                'ip': ip,
                'mac': mac,
                'description': f'⚠️ Services vulnérables sur {ip}',
                'details': f'Services à risque : {" | ".join(port_details)}',
                'recommendation': 'Vérifiez cet appareil. Services sensibles exposés ou outils d\'exploitation détectés.'
            })
            
            print(f"   ⚠️  HAUTE : {ip} - Services vulnérables : {port_details}")
        
        # ========== ALERTE MOYENNE : SERVICES SUSPECTS ==========
        elif detected_medium:
            port_details = [f"Port {p['port']} ({p['name']})" for p in detected_medium]
            
            threats.append({
                'type': 'SUSPICIOUS_SERVICE',
                'severity': 'MEDIUM',
                'ip': ip,
                'mac': mac,
                'description': f'ℹ️ Services suspects sur {ip}',
                'details': f'Ports inhabituels : {" | ".join(port_details)}',
                'recommendation': 'Configuration inhabituelle détectée. Vérifiez si ces services sont légitimes.'
            })
            
            print(f"   ℹ️  MOYENNE : {ip} - Services suspects : {port_details}")
        
        return threats
    
    def detect_distributed_ddos(self, current_devices):
        threats = []
        # Chercher appareils avec TROP de ports suspects
        suspicious_ips = [d.get('ip', '') for d in current_devices if d.get('suspicious_port_count', 0) >= 3]
        
        # Alerte si PLUSIEURS appareils avec backdoors (botnet)
        if len(suspicious_ips) >= 3:
            threats.append({
                'type': 'DDOS_DISTRIBUTED',
                'severity': 'CRITICAL',
                'description': f'🚨 Botnet détecté!',
                'details': f'{len(suspicious_ips)} appareils avec ports suspects',
                'recommendation': 'Botnet possible - Isolez ces appareils immédiatement!'
            })
        return threats
    
    def detect_arp_spoofing(self, ip, mac):
        threats = []
        if ip in self.ip_mac_history:
            previous_macs = self.ip_mac_history[ip]
            if mac not in previous_macs and len(previous_macs) > 0:
                threats.append({
                    'type': 'ARP_SPOOFING',
                    'severity': 'CRITICAL',
                    'ip': ip,
                    'mac': mac,
                    'description': f'🚨 ARP Spoofing! {ip} changé de MAC',
                    'details': f'Ancienne: {previous_macs[-1]} → Nouvelle: {mac}',
                    'recommendation': 'MITM possible - Isolez immédiatement.'
                })
        return threats
    
    def detect_mac_spoofing(self, ip, mac):
        threats = []
        if mac in self.mac_ip_history:
            previous_ips = self.mac_ip_history[mac]
            if ip not in previous_ips and len(previous_ips) > 0:
                threats.append({
                    'type': 'MAC_SPOOFING',
                    'severity': 'HIGH',
                    'ip': ip,
                    'mac': mac,
                    'description': f'⚠️ MAC Spoofing! {mac} utilise nouvelle IP',
                    'details': f'IPs précédentes: {", ".join(previous_ips[-3:])}',
                    'recommendation': 'Vérifiez cet appareil.'
                })
        return threats
    
    def detect_gateway_spoofing(self, mac):
        threats = []
        if self.gateway_mac is None:
            self.gateway_mac = mac
        elif self.gateway_mac != mac:
            threats.append({
                'type': 'MITM_GATEWAY',
                'severity': 'CRITICAL',
                'mac': mac,
                'description': f'🔴 MITM Gateway! MAC routeur changé',
                'details': f'Ancienne: {self.gateway_mac} → Nouvelle: {mac}',
                'recommendation': 'DANGER CRITIQUE!'
            })
            self.gateway_mac = mac
        return threats
    
    def detect_unauthorized_device(self, mac):
        threats = []
        if len(WHITELIST) > 0 and mac not in WHITELIST:
            threats.append({
                'type': 'UNAUTHORIZED_DEVICE',
                'severity': 'MEDIUM',
                'mac': mac,
                'description': f'⚡ Appareil non autorisé',
                'recommendation': 'Vérifiez cet appareil.'
            })
        return threats
    
    def detect_blacklisted_device(self, mac, ip):
        threats = []
        if ip in BLACKLIST:
            threats.append({
                'type': 'BLACKLISTED_DEVICE',
                'severity': 'CRITICAL',
                'mac': mac,
                'ip': ip,
                'description': f'🚫 IP blacklistée: {ip}',
                'recommendation': 'Bloquez immédiatement.'
            })
        return threats
    
    def detect_disappeared_devices(self, current_devices):
        threats = []
        current_ips = {d['ip'] for d in current_devices}
        previous_ips = set(self.previous_scan.keys())
        disappeared = previous_ips - current_ips
        if len(disappeared) >= 3:
            threats.append({
                'type': 'DEAUTH_ATTACK',
                'severity': 'HIGH',
                'description': f'⚠️ Déconnexion massive! {len(disappeared)} appareils',
                'details': f'IPs disparues: {", ".join(list(disappeared)[:5])}',
                'recommendation': 'Possible attaque deauth - Vérifiez le routeur.'
            })
        return threats
    
    def update_history(self, ip, mac, open_ports=None):
        if ip not in self.mac_ip_history[mac]:
            self.mac_ip_history[mac].append(ip)
            if len(self.mac_ip_history[mac]) > 5:
                self.mac_ip_history[mac].pop(0)
        
        if mac not in self.ip_mac_history[ip]:
            self.ip_mac_history[ip].append(mac)
            if len(self.ip_mac_history[ip]) > 5:
                self.ip_mac_history[ip].pop(0)

detector = AttackDetector()

def clean_expired_alerts():
    global current_alerts
    now = datetime.now()
    current_alerts = [
        alert for alert in current_alerts
        if 'timestamp_obj' in alert and (now - alert['timestamp_obj']).total_seconds() < (ALERT_EXPIRATION_MINUTES * 60)
    ]

def update_current_stats():
    global current_stats
    clean_expired_alerts()
    current_stats['total_devices'] = len(devices_database)
    current_stats['alert_count'] = len([a for a in current_alerts if a.get('severity') in ['CRITICAL', 'HIGH']])
    current_stats['network_packets'] = last_ddos_stats.get('total_packets', 0)
    current_stats['packets_per_sec'] = last_ddos_stats.get('packets_per_sec', 0)
    current_stats['ddos_count'] = len([a for a in current_alerts if 'DDOS' in a.get('type', '')])
    current_stats['backdoor_count'] = len([a for a in current_alerts if a.get('type') in ['BACKDOOR_TROJAN', 'VULNERABLE_SERVICE', 'SUSPICIOUS_SERVICE']])  # ✅ CHANGÉ
    current_stats['last_scan'] = scan_history[-1]['timestamp'] if scan_history else 'Aucun'
    current_stats['status'] = 'THREAT' if current_stats['alert_count'] > 0 else 'SECURE'

# ==================== API ====================
@app.route('/api/current_stats')
def get_current_stats():
    clean_expired_alerts()
    update_current_stats()
    return jsonify(current_stats)

@app.route('/api/current_alerts')
def get_current_alerts():
    clean_expired_alerts()
    return jsonify({'alerts': current_alerts})

@app.route('/api/alert_history')
def get_alert_history():
    return jsonify({'alerts': alerts[-100:] if alerts else []})

@app.route('/api/devices')
def get_devices():
    devices_with_suspicious = {}
    for mac, info in devices_database.items():
        devices_with_suspicious[mac] = {
            **info,
            'suspicious_ports': info.get('suspicious_ports', [])  # ✅ NOUVEAU
        }
    return jsonify({'devices': devices_with_suspicious})

@app.route('/scan', methods=['POST'])
def receive_scan():
    try:
        global last_ddos_stats, current_alerts
        
        data = request.get_json()
        timestamp_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        timestamp_obj = datetime.now()
        data['timestamp'] = timestamp_str
        
        clean_expired_alerts()
        
        ddos_data = data.get('ddos_detection', {})
        total_packets = ddos_data.get('total_packets', 0)
        packets_per_sec = ddos_data.get('packets_per_sec', 0)
        top_sources = ddos_data.get('top_sources', [])
        
        last_ddos_stats = {
            'total_packets': total_packets,
            'packets_per_sec': packets_per_sec,
            'capture_time': timestamp_str
        }
        
        print(f"\n{'='*60}")
        print(f"📡 SCAN - {timestamp_str}")
        print(f"📊 Appareils: {len(data.get('devices', []))}")
        print(f"🔥 Paquets: {total_packets:,} ({packets_per_sec:,} pkt/s)")
        # Calculate dominant source percentage for DDoS analysis
        dominant_percentage = 0
        if total_packets > 0 and len(top_sources) > 0:
            dominant_count = top_sources[0].get('packet_count', 0)
            dominant_percentage = (dominant_count / total_packets) * 100
        print(f"📈 Analyse DDoS:")
        print(f"   - Total paquets: {total_packets:,} ({packets_per_sec:,} pkt/s)")
        print(f"   - Source dominante: {dominant_percentage:.1f}% du trafic")
        print(f"   - Seuils: 50k (40%), 100k (50%), 200k (60%)")
        if total_packets < 2000:
            print(f"   ✅ Trafic NORMAL (< 2,000 paquets) [MODE TEST]")
        elif dominant_percentage < 40:
            print(f"   ✅ Trafic distribué (pas de concentration suspecte)")
       
        mac_to_ip = {}
        for device in data.get('devices', []):
            mac = device.get('mac', '').upper()
            ip = device.get('ip', '')
            if mac and ip:
                try:
                    mac_suffix = int(mac.split(':')[-1], 16)
                    mac_to_ip[mac_suffix] = {'ip': ip, 'mac': mac}
                except (ValueError, IndexError):
                    pass
        
        dominant_source = None
        if len(top_sources) > 0:
            mac_suffix = top_sources[0].get('mac_suffix', 0)
            if mac_suffix in mac_to_ip:
                dominant_source = mac_to_ip[mac_suffix]
            else:
                for device in data.get('devices', []):
                    ip = device.get('ip', '')
                    mac = device.get('mac', '').upper()
                    if ip not in TRUSTED_IPS:
                        dominant_source = {'ip': ip, 'mac': mac}
                        break
        
        # ========== ALERTES DDoS ==========
        ddos_threats = []
        dominant_percentage = 0
        if dominant_source and len(top_sources) > 0 and total_packets > 0:
            dominant_percentage = (top_sources[0].get('packet_count', 0) / total_packets) * 100

        if total_packets > 10000:
            threat_data = {
                'type': 'DDOS_NETWORK_FLOOD',
                'severity': 'CRITICAL',
                'details': f'{total_packets:,} frames WiFi ({packets_per_sec:,} frames/s)',
                'recommendation': 'CRITIQUE! Volume détecté',
                'timestamp': timestamp_str,
                'timestamp_obj': timestamp_obj
            }
            if dominant_source:
                threat_data['ip'] = dominant_source['ip']
                threat_data['mac'] = dominant_source['mac']
                threat_data['description'] = f'🚨 DDOS FLOOD! {dominant_source["ip"]} ({dominant_percentage:.1f}%)'
            else:
                threat_data['description'] = f'🚨 DDOS FLOOD! ({total_packets:,} frames)'
            ddos_threats.append(threat_data)
                
        elif total_packets > 5000:
            threat_data = {
                'type': 'DDOS_HIGH_TRAFFIC',
                'severity': 'HIGH',
                'details': f'{total_packets:,} frames WiFi ({packets_per_sec:,} frames/s)',
                'recommendation': 'Trafic élevé',
                'timestamp': timestamp_str,
                'timestamp_obj': timestamp_obj
            }
            if dominant_source:
                threat_data['ip'] = dominant_source['ip']
                threat_data['mac'] = dominant_source['mac']
                threat_data['description'] = f'⚠️ Trafic élevé - {dominant_source["ip"]} ({dominant_percentage:.1f}%)'
            else:
                threat_data['description'] = f'⚠️ Trafic élevé ({total_packets:,} frames)'
            ddos_threats.append(threat_data)
                
        elif total_packets > 3000:
            threat_data = {
                'type': 'DDOS_MODERATE_TRAFFIC',
                'severity': 'MEDIUM',
                'details': f'{total_packets:,} frames WiFi',
                'recommendation': 'Surveiller',
                'timestamp': timestamp_str,
                'timestamp_obj': timestamp_obj
            }
            if dominant_source:
                threat_data['ip'] = dominant_source['ip']
                threat_data['mac'] = dominant_source['mac']
                threat_data['description'] = f'ℹ️ Trafic concentré - {dominant_source["ip"]} ({dominant_percentage:.1f}%)'
            else:
                threat_data['description'] = f'ℹ️ Trafic concentré ({total_packets:,} frames)'
            ddos_threats.append(threat_data)
        
        current_alerts = [a for a in current_alerts if 'DDOS' not in a.get('type', '')]
        
        for threat in ddos_threats:
            alerts.append(threat)
            current_alerts.append(threat)
            attack_stats[threat['type']] += 1
            print(f"   🚨 DDoS: {threat['description']}")
        
        # ========== ANALYSE RÉSEAU (incluant ports suspects) ==========
        threats = detector.analyze(data)
        
        backdoor_threats = [t for t in threats if t.get('type') in ['BACKDOOR_TROJAN', 'VULNERABLE_SERVICE', 'SUSPICIOUS_SERVICE']]
        other_threats = [t for t in threats if t.get('type') not in ['BACKDOOR_TROJAN', 'VULNERABLE_SERVICE', 'SUSPICIOUS_SERVICE']]
        
        for threat in threats:
            threat['timestamp'] = timestamp_str
            threat['timestamp_obj'] = timestamp_obj
            alerts.append(threat)
            
            is_duplicate = any(
                a.get('type') == threat['type'] and 
                a.get('ip') == threat.get('ip') 
                for a in current_alerts
            )
            if not is_duplicate:
                current_alerts.append(threat)
                attack_stats[threat['type']] += 1
        
        if len(alerts) > 200:
            alerts[:] = alerts[-200:]
        
        critical_alerts = len([t for t in threats + ddos_threats if t['severity'] in ['CRITICAL', 'HIGH']])
        alert_history.append({'timestamp': timestamp_str, 'count': critical_alerts})
        device_count_history.append({'timestamp': timestamp_str, 'count': len(data.get('devices', []))})
        
        scan_history.append(data)
        if len(scan_history) > MAX_HISTORY:
            scan_history.pop(0)
        
        for device in data.get('devices', []):
            mac = device.get('mac', '').upper()
            if mac:
                if mac not in devices_database:
                    devices_database[mac] = {
                        'first_seen': timestamp_str,
                        'ips': [],
                        'type': device.get('type', 'U'),
                        'open_ports': [],
                        'suspicious_ports': []  # ✅ NOUVEAU
                    }
                ip = device.get('ip', '')
                if ip and ip not in devices_database[mac]['ips']:
                    devices_database[mac]['ips'].append(ip)
                devices_database[mac]['open_ports'] = device.get('open_ports', [])
                devices_database[mac]['suspicious_ports'] = device.get('suspicious_ports', [])  # ✅ NOUVEAU
                devices_database[mac]['last_seen'] = timestamp_str
        
        update_current_stats()
        
        print(f"✅ Menaces détectées:")
        print(f"   - DDoS: {len(ddos_threats)}")
        print(f"   - Backdoor/Vulnérables: {len(backdoor_threats)}")
        print(f"   - Autres: {len(other_threats)}")
        print(f"   - Total: {len(threats) + len(ddos_threats)}")
        print(f"🔥 Alertes actives: {len(current_alerts)}")
        print(f"{'='*60}\n")
        
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        import traceback
        print(f"❌ Erreur: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/api/activity')
def get_activity():
    return jsonify({'alerts': list(alert_history), 'devices': list(device_count_history)})

@app.route('/api/blacklist', methods=['GET'])
def get_blacklist():
    return jsonify({'blacklist': BLACKLIST})

@app.route('/api/blacklist/add', methods=['POST'])
def add_to_blacklist():
    try:
        data = request.get_json()
        ip = data.get('ip', '').strip()
        if not ip:
            return jsonify({'status': 'error', 'message': 'IP vide'}), 400
        parts = ip.split('.')
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return jsonify({'status': 'error', 'message': 'Format invalide'}), 400
        if ip in BLACKLIST:
            return jsonify({'status': 'error', 'message': 'Déjà blacklistée'}), 400
        if ip in TRUSTED_IPS:
            return jsonify({'status': 'error', 'message': 'IP de confiance'}), 400
        BLACKLIST.append(ip)
        print(f"🚫 IP blacklistée: {ip}")
        return jsonify({'status': 'success', 'blacklist': BLACKLIST})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/blacklist/remove', methods=['POST'])
def remove_from_blacklist():
    try:
        data = request.get_json()
        ip = data.get('ip', '').strip()
        if ip not in BLACKLIST:
            return jsonify({'status': 'error', 'message': 'Non trouvée'}), 404
        BLACKLIST.remove(ip)
        print(f"✅ IP retirée: {ip}")
        return jsonify({'status': 'success', 'blacklist': BLACKLIST})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/clear_alerts', methods=['POST'])
def clear_alerts_route():
    global alerts, attack_stats, current_alerts
    alerts = []
    current_alerts = []
    attack_stats = defaultdict(int)
    update_current_stats()
    print("🧹 Alertes effacées")
    return jsonify({'status': 'success'})

# ✅ NOUVEAU : Endpoint pour réinitialiser l'historique
@app.route('/api/reset_history', methods=['POST'])
def reset_history():
    """Réinitialise l'historique (utile après fermeture des ports de test)"""
    global detector
    detector.port_scan_history.clear() if hasattr(detector, 'port_scan_history') else None
    print("🔄 Historique réinitialisé")
    return jsonify({'status': 'success', 'message': 'Historique réinitialisé'})

@app.route('/')
def dashboard():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>WiFi Monitor </title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Inter', -apple-system, sans-serif;
                background: linear-gradient(135deg, #1a1a2e, #16213e, #0f3460, #533483);
                color: #fff;
                min-height: 100vh;
                overflow-x: hidden;
            }
            
            .history-sidebar {
                position: fixed;
                top: 0;
                right: -450px;
                width: 450px;
                height: 100vh;
                background: linear-gradient(135deg, rgba(20, 20, 35, 0.98), rgba(15, 15, 25, 0.98));
                backdrop-filter: blur(20px);
                box-shadow: -5px 0 30px rgba(0,0,0,0.5);
                transition: right 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55);
                z-index: 2000;
                display: flex;
                flex-direction: column;
                border-left: 2px solid rgba(239, 83, 80, 0.3);
            }
            .history-sidebar.open { right: 0; }
            .sidebar-header {
                padding: 25px;
                border-bottom: 2px solid rgba(239, 83, 80, 0.3);
                display: flex;
                justify-content: space-between;
                align-items: center;
                background: rgba(239, 83, 80, 0.1);
            }
            .sidebar-title {
                font-size: 1.4em;
                font-weight: 700;
                color: #ef5350;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .close-sidebar {
                background: rgba(255, 23, 68, 0.2);
                border: 2px solid rgba(255, 23, 68, 0.4);
                color: #ff5252;
                border-radius: 8px;
                padding: 8px 16px;
                cursor: pointer;
                font-weight: 700;
                transition: all 0.3s;
            }
            .close-sidebar:hover {
                background: rgba(255, 23, 68, 0.4);
                transform: scale(1.05);
            }
            .sidebar-content {
                flex: 1;
                overflow-y: auto;
                padding: 20px;
            }
            .history-alert {
                background: rgba(30, 30, 50, 0.6);
                padding: 15px;
                margin: 12px 0;
                border-radius: 8px;
                border-left: 4px solid;
                transition: all 0.3s;
            }
            .history-alert:hover {
                background: rgba(30, 30, 50, 0.9);
                transform: translateX(-5px);
            }
            .history-alert.critical { border-color: #ff1744; }
            .history-alert.high { border-color: #ff6f00; }
            .history-alert.medium { border-color: #ffab00; }
            
            .history-toggle-btn {
                position: fixed;
                top: 20px;
                right: 20px;
                background: linear-gradient(135deg, #ff1744, #f50057);
                color: white;
                border: none;
                padding: 12px 20px;
                border-radius: 8px;
                font-weight: 700;
                cursor: pointer;
                z-index: 1999;
                box-shadow: 0 4px 15px rgba(255, 23, 68, 0.4);
                transition: all 0.3s;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            .history-toggle-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(255, 23, 68, 0.6);
            }
            .history-badge {
                background: #fff;
                color: #ff1744;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 0.85em;
                font-weight: 800;
            }
            
            .container {
                max-width: 1800px;
                margin: 0 auto;
                padding: 20px;
                position: relative;
                z-index: 1;
            }
            
            .header {
                text-align: center;
                margin-bottom: 30px;
                padding: 30px;
                background: linear-gradient(135deg, rgba(30, 30, 50, 0.95), rgba(20, 20, 40, 0.9));
                border-radius: 12px;
                backdrop-filter: blur(15px);
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
                border: 1px solid rgba(239, 83, 80, 0.2);
            }
            
            .main-title {
                font-size: 2.5em;
                font-weight: 700;
                margin-bottom: 15px;
                background: linear-gradient(135deg, #ef5350, #ff6f00, #ff1744);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                letter-spacing: -0.5px;
            }
            
            .detection-list {
                display: flex;
                flex-wrap: wrap;
                justify-content: center;
                gap: 8px;
                margin-top: 15px;
            }
            
            .detection-badge {
                padding: 6px 14px;
                background: rgba(239, 83, 80, 0.15);
                border: 1px solid rgba(239, 83, 80, 0.3);
                border-radius: 20px;
                font-size: 0.75em;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                color: #ffccbc;
            }
            
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(6, 1fr);
                gap: 15px;
                margin-bottom: 30px;
            }
            
            .stat-card {
                background: linear-gradient(135deg, rgba(30, 30, 50, 0.95), rgba(20, 20, 40, 0.9));
                padding: 20px;
                border-radius: 10px;
                border: 1px solid rgba(239, 83, 80, 0.2);
                backdrop-filter: blur(10px);
                text-align: center;
                transition: all 0.3s;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
                position: relative;
            }
            
            @keyframes updatePulse {
                0%, 100% { 
                    border-color: rgba(239, 83, 80, 0.2);
                    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
                }
                50% { 
                    border-color: rgba(239, 83, 80, 0.6);
                    box-shadow: 0 8px 25px rgba(239, 83, 80, 0.3);
                }
            }
            
            .stat-card.updating {
                animation: updatePulse 0.8s ease-in-out;
            }
            
            .stat-card:hover {
                transform: translateY(-5px);
                border-color: rgba(239, 83, 80, 0.5);
                box-shadow: 0 8px 25px rgba(239, 83, 80, 0.3);
            }
            
            .stat-label {
                color: #b0bec5;
                font-size: 0.75em;
                text-transform: uppercase;
                letter-spacing: 1px;
                font-weight: 700;
                margin-bottom: 12px;
            }
            
            .stat-number {
                font-size: 2.8em;
                font-weight: 800;
                margin: 10px 0;
                line-height: 1;
                font-family: 'SF Mono', monospace;
                transition: all 0.3s;
            }
            
            .stat-sublabel {
                color: #78909c;
                font-size: 0.7em;
                margin-top: 8px;
            }
            
            .critical { color: #ff1744; text-shadow: 0 0 20px rgba(255, 23, 68, 0.5); }
            .high { color: #ff6f00; text-shadow: 0 0 15px rgba(255, 111, 0, 0.5); }
            .safe { color: #00e676; text-shadow: 0 0 15px rgba(0, 230, 118, 0.5); }
            .neutral { color: #78909c; }
            
            .status-badge {
                padding: 10px 22px;
                border-radius: 6px;
                font-weight: 700;
                font-size: 1em;
                text-transform: uppercase;
                letter-spacing: 1px;
                font-family: 'SF Mono', monospace;
                transition: all 0.3s;
            }
            
            .status-safe {
                background: rgba(0, 230, 118, 0.15);
                color: #00e676;
                border: 2px solid #00e676;
                box-shadow: 0 0 20px rgba(0, 230, 118, 0.3);
            }
            
            .status-danger {
                background: rgba(255, 23, 68, 0.15);
                color: #ff1744;
                border: 2px solid #ff1744;
                box-shadow: 0 0 20px rgba(255, 23, 68, 0.3);
                animation: pulse 2s infinite;
            }
            
            @keyframes pulse {
                0%, 100% { box-shadow: 0 0 20px rgba(255, 23, 68, 0.3); }
                50% { box-shadow: 0 0 30px rgba(255, 23, 68, 0.6); }
            }
            
            .live-indicator {
                position: absolute;
                top: 10px;
                right: 10px;
                width: 8px;
                height: 8px;
                background: #00e676;
                border-radius: 50%;
                box-shadow: 0 0 10px #00e676;
                animation: blink 2s infinite;
            }
            
            @keyframes blink {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.3; }
            }
            
            .chart-section {
                background: linear-gradient(135deg, rgba(30, 30, 50, 0.95), rgba(20, 20, 40, 0.9));
                padding: 30px;
                border-radius: 12px;
                border: 1px solid rgba(239, 83, 80, 0.2);
                backdrop-filter: blur(10px);
                margin-bottom: 30px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
            }
            
            .chart-title {
                font-size: 1.5em;
                font-weight: 700;
                margin-bottom: 20px;
            }
            
            .chart-container {
                position: relative;
                height: 350px;
            }
            
            .section {
                background: linear-gradient(135deg, rgba(30, 30, 50, 0.95), rgba(20, 20, 40, 0.9));
                padding: 30px;
                border-radius: 12px;
                border: 1px solid rgba(239, 83, 80, 0.2);
                backdrop-filter: blur(10px);
                margin-bottom: 30px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
            }
            
            .section-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 25px;
                padding-bottom: 15px;
                border-bottom: 1px solid rgba(239, 83, 80, 0.2);
            }
            
            h2 {
                font-size: 1.5em;
                font-weight: 700;
            }
            
            .section-count {
                background: rgba(239, 83, 80, 0.2);
                border: 1px solid rgba(239, 83, 80, 0.3);
                padding: 5px 15px;
                border-radius: 20px;
                font-weight: 700;
                color: #ff5252;
                transition: all 0.3s;
            }
            
            .alert {
                padding: 20px;
                margin: 15px 0;
                border-radius: 8px;
                border-left: 4px solid;
                background: rgba(30, 30, 50, 0.5);
                transition: all 0.3s;
            }
            
            .alert:hover {
                transform: translateX(5px);
                background: rgba(30, 30, 50, 0.7);
            }
            
            .alert-critical { border-color: #ff1744; }
            .alert-high { border-color: #ff6f00; }
            .alert-medium { border-color: #ffab00; }
            
            .alert-header {
                display: flex;
                justify-content: space-between;
                margin-bottom: 12px;
            }
            
            .alert-title {
                font-weight: 600;
                font-size: 1.05em;
                flex: 1;
            }
            
            .alert-details {
                color: #b0bec5;
                margin: 8px 0;
                font-size: 0.9em;
                line-height: 1.6;
            }
            
            .badge {
                display: inline-block;
                padding: 4px 12px;
                border-radius: 4px;
                font-size: 0.7em;
                font-weight: 700;
                text-transform: uppercase;
            }
            
            .badge-critical { background: #ff1744; color: white; }
            .badge-high { background: #ff6f00; color: white; }
            .badge-medium { background: #ffab00; color: black; }
            
            .blacklist-form {
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
            }
            
            .blacklist-input {
                flex: 1;
                padding: 12px 18px;
                background: rgba(30, 30, 50, 0.6);
                border: 2px solid rgba(239, 83, 80, 0.3);
                border-radius: 8px;
                color: #fff;
                font-size: 0.95em;
                font-family: 'SF Mono', monospace;
                transition: all 0.3s;
            }
            
            .blacklist-input:focus {
                outline: none;
                border-color: rgba(239, 83, 80, 0.6);
                background: rgba(30, 30, 50, 0.8);
            }
            
            .blacklist-input::placeholder {
                color: #78909c;
            }
            
            .blacklist-btn {
                padding: 12px 24px;
                background: linear-gradient(135deg, #ff1744, #f50057);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 0.9em;
                font-weight: 700;
                cursor: pointer;
                transition: all 0.3s;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            
            .blacklist-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(255, 23, 68, 0.5);
            }
            
            .blacklist-item {
                display: flex;
                justify-content: space-between;
                align-items: center;
                background: rgba(30, 30, 50, 0.5);
                padding: 15px;
                margin: 10px 0;
                border-radius: 8px;
                border-left: 3px solid #ff1744;
                transition: all 0.3s;
            }
            
            .blacklist-item:hover {
                transform: translateX(5px);
                background: rgba(30, 30, 50, 0.7);
            }
            
            .blacklist-ip {
                font-family: 'SF Mono', monospace;
                font-weight: 700;
                color: #ff5252;
                font-size: 1.1em;
            }
            
            .remove-btn {
                padding: 8px 16px;
                background: rgba(255, 23, 68, 0.2);
                border: 1px solid rgba(255, 23, 68, 0.4);
                border-radius: 6px;
                color: #ff5252;
                font-size: 0.85em;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s;
            }
            
            .remove-btn:hover {
                background: rgba(255, 23, 68, 0.3);
                border-color: rgba(255, 23, 68, 0.6);
            }
            
            .device-item {
                display: flex;
                justify-content: space-between;
                align-items: center;
                background: rgba(30, 30, 50, 0.5);
                padding: 18px;
                margin: 12px 0;
                border-radius: 8px;
                border-left: 3px solid #ef5350;
                transition: all 0.3s;
            }
            
            .device-item:hover {
                transform: translateX(5px);
                background: rgba(30, 30, 50, 0.7);
                border-color: #ff1744;
            }
            
            .device-main { flex: 1; }
            
            .device-mac {
                font-family: 'SF Mono', monospace;
                font-weight: 700;
                color: #ff5252;
                font-size: 1em;
                margin-bottom: 8px;
            }
            
            .device-details {
                color: #b0bec5;
                font-size: 0.85em;
                display: flex;
                gap: 15px;
                flex-wrap: wrap;
            }
            
            .device-detail {
                display: flex;
                align-items: center;
                gap: 5px;
            }
            
            .empty-state {
                text-align: center;
                padding: 60px 20px;
                color: #78909c;
            }
            
            .empty-state-title {
                color: #00e676;
                font-size: 1.5em;
                margin-bottom: 10px;
                font-weight: 700;
            }
            
            @media (max-width: 768px) {
                .stats-grid { grid-template-columns: repeat(3, 1fr); }
                .history-sidebar { width: 100%; right: -100%; }
            }
        </style>
    </head>
    <body>
        <button class="history-toggle-btn" onclick="toggleHistory()">
             HISTORIQUE
            <span class="history-badge" id="historyCount">0</span>
        </button>
        
        <div class="history-sidebar" id="historySidebar">
            <div class="sidebar-header">
                <div class="sidebar-title">
                    <span></span>
                    <span>HISTORIQUE</span>
                </div>
                <button class="close-sidebar" onclick="toggleHistory()">✖ FERMER</button>
            </div>
            <div class="sidebar-content" id="historyContent">
                <div class="empty-state">
                    <div class="empty-state-title">✅ Aucun historique</div>
                </div>
            </div>
        </div>
        
        <div class="container">
            <div class="header">
                <div class="main-title">🛡️ WIFI SECURITY MONITOR </div>
                <div class="detection-list">
                    <span class="detection-badge">📡 DDoS</span>
                    <span class="detection-badge">🚨 ARP Spoofing</span>
                    <span class="detection-badge">🎭 MAC Spoofing</span>
                    <span class="detection-badge">🔴 MITM</span>
                    <span class="detection-badge">🔍 Ports Suspects</span>
                    <span class="detection-badge">⚡ Deauth</span>
                </div>
            </div>
            
            <div class="stats-grid" id="statsGrid"></div>
            
            <div class="chart-section">
                <div class="chart-title">📊 ACTIVITÉ RÉSEAU</div>
                <div class="chart-container">
                    <canvas id="activityChart"></canvas>
                </div>
            </div>
            
            <div class="section">
                <div class="section-header">
                    <h2>🚨 ALERTES ACTUELLES</h2>
                    <span class="section-count" id="currentAlertCount">0</span>
                </div>
                <div id="currentAlertsContainer">
                    <div class="empty-state">
                        <div class="empty-state-title">✅ SYSTÈME SÉCURISÉ</div>
                        <p>Aucune menace active</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <div class="section-header">
                    <h2>🚫 BLACKLIST IP</h2>
                    <span class="section-count" id="blacklistCount">0</span>
                </div>
                <div class="blacklist-form">
                    <input 
                        type="text" 
                        id="blacklistInput" 
                        class="blacklist-input" 
                        placeholder="192.168.1.x"
                    >
                    <button class="blacklist-btn" onclick="addToBlacklist()">
                        ➕ AJOUTER
                    </button>
                </div>
                <div id="blacklistContainer"></div>
            </div>
            
            <div class="section">
                <div class="section-header">
                    <h2>📱 APPAREILS</h2>
                    <span class="section-count" id="deviceCount">0</span>
                </div>
                <div id="devicesContainer"></div>
            </div>
        </div>
        
        <script>
            const ctx = document.getElementById('activityChart').getContext('2d');
            const activityChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Alertes',
                        data: [],
                        borderColor: '#ff1744',
                        backgroundColor: 'rgba(255, 23, 68, 0.1)',
                        borderWidth: 3,
                        tension: 0.4,
                        fill: true,
                        yAxisID: 'y'
                    }, {
                        label: 'Appareils',
                        data: [],
                        borderColor: '#00e676',
                        backgroundColor: 'rgba(0, 230, 118, 0.1)',
                        borderWidth: 3,
                        tension: 0.4,
                        fill: true,
                        yAxisID: 'y1'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: { color: '#fff', font: { size: 14, weight: 600 } }
                        }
                    },
                    scales: {
                        x: {
                            grid: { color: 'rgba(255, 255, 255, 0.05)' },
                            ticks: { color: '#b0bec5' }
                        },
                        y: {
                            position: 'left',
                            grid: { color: 'rgba(255, 255, 255, 0.05)' },
                            ticks: { color: '#ff5252' },
                            title: { display: true, text: 'Alertes', color: '#ff5252' }
                        },
                        y1: {
                            position: 'right',
                            grid: { drawOnChartArea: false },
                            ticks: { color: '#00e676' },
                            title: { display: true, text: 'Appareils', color: '#00e676' }
                        }
                    }
                }
            });
            
            async function updateStats() {
                try {
                    const response = await fetch('/api/current_stats');
                    const stats = await response.json();
                    
                    const statsGrid = document.getElementById('statsGrid');
                    statsGrid.classList.add('updating');
                    setTimeout(() => statsGrid.classList.remove('updating'), 800);
                    
                    statsGrid.innerHTML = `
                        <div class="stat-card">
                            <div class="live-indicator"></div>
                            <div class="stat-label">Appareils</div>
                            <div class="stat-number safe">${stats.total_devices}</div>
                            <div class="stat-sublabel">Connectés</div>
                        </div>
                        <div class="stat-card">
                            <div class="live-indicator"></div>
                            <div class="stat-label">Alertes</div>
                            <div class="stat-number ${stats.alert_count > 0 ? 'critical' : 'safe'}">${stats.alert_count}</div>
                            <div class="stat-sublabel">Actives</div>
                        </div>
                        <div class="stat-card">
                            <div class="live-indicator"></div>
                            <div class="stat-label">Trafic</div>
                            <div class="stat-number ${stats.network_packets > 200000 ? 'critical' : stats.network_packets > 100000 ? 'high' : 'safe'}">${stats.network_packets.toLocaleString()}</div>
                            <div class="stat-sublabel">${stats.packets_per_sec} pkt/s</div>
                        </div>
                        <div class="stat-card">
                            <div class="live-indicator"></div>
                            <div class="stat-label">DDoS</div>
                            <div class="stat-number ${stats.ddos_count > 0 ? 'critical' : 'neutral'}">${stats.ddos_count}</div>
                            <div class="stat-sublabel">Détectées</div>
                        </div>
                        <div class="stat-card">
                            <div class="live-indicator"></div>
                            <div class="stat-label">Dernier Scan</div>
                            <div class="stat-number" style="font-size:1.2em; color:#ff5252;">${stats.last_scan.split(' ')[1] || '--:--:--'}</div>
                            <div class="stat-sublabel">Horodatage</div>
                        </div>
                        <div class="stat-card">
                            <div class="live-indicator"></div>
                            <div class="stat-label">Status</div>
                            <div style="margin-top: 10px;">
                                <span class="status-badge status-${stats.status === 'SECURE' ? 'safe' : 'danger'}">${stats.status}</span>
                            </div>
                        </div>
                    `;
                } catch (error) {
                    console.error('❌ Erreur stats:', error);
                }
            }
            
            async function updateChart() {
                try {
                    const response = await fetch('/api/activity');
                    const data = await response.json();
                    if (data.alerts && data.alerts.length > 0) {
                        activityChart.data.labels = data.alerts.map(item => item.timestamp.split(' ')[1]);
                        activityChart.data.datasets[0].data = data.alerts.map(item => item.count);
                        activityChart.data.datasets[1].data = data.devices.map(item => item.count);
                        activityChart.update('none');
                    }
                } catch (error) {
                    console.error('❌ Erreur graphique:', error);
                }
            }
            
            async function updateCurrentAlerts() {
                try {
                    const response = await fetch('/api/current_alerts');
                    const data = await response.json();
                    const alerts = data.alerts || [];
                    
                    document.getElementById('currentAlertCount').textContent = alerts.length;
                    
                    if (alerts.length === 0) {
                        document.getElementById('currentAlertsContainer').innerHTML = `
                            <div class="empty-state">
                                <div class="empty-state-title">✅ SYSTÈME SÉCURISÉ</div>
                                <p>Aucune menace active</p>
                            </div>
                        `;
                    } else {
                        document.getElementById('currentAlertsContainer').innerHTML = alerts.map(alert => `
                            <div class="alert alert-${alert.severity.toLowerCase()}">
                                <div class="alert-header">
                                    <div class="alert-title">${alert.description}</div>
                                    <span class="badge badge-${alert.severity.toLowerCase()}">${alert.severity}</span>
                                </div>
                                ${alert.ip ? `<div class="alert-details"><strong>🎯 IP:</strong> ${alert.ip}</div>` : ''}
                                ${alert.mac ? `<div class="alert-details"><strong>🔖 MAC:</strong> ${alert.mac}</div>` : ''}
                                ${alert.details ? `<div class="alert-details">${alert.details}</div>` : ''}
                                <div class="alert-details"><strong>💡</strong> ${alert.recommendation}</div>
                            </div>
                        `).join('');
                    }
                } catch (error) {
                    console.error('❌ Erreur alertes:', error);
                }
            }
            
            async function loadHistory() {
                try {
                    const response = await fetch('/api/alert_history');
                    const data = await response.json();
                    const alerts = data.alerts || [];
                    
                    document.getElementById('historyCount').textContent = alerts.length;
                    
                    if (alerts.length === 0) {
                        document.getElementById('historyContent').innerHTML = `
                            <div class="empty-state">
                                <div class="empty-state-title">✅ Aucun historique</div>
                            </div>
                        `;
                    } else {
                        document.getElementById('historyContent').innerHTML = alerts.reverse().map(alert => `
                            <div class="history-alert ${alert.severity.toLowerCase()}">
                                <div style="font-weight:700; margin-bottom:8px;">${alert.description}</div>
                                ${alert.ip ? `<div style="color:#ff5252; font-size:0.9em;">🎯 ${alert.ip}</div>` : ''}
                                ${alert.mac ? `<div style="color:#ffa726; font-size:0.85em;">🔖 ${alert.mac}</div>` : ''}
                                ${alert.details ? `<div style="color:#b0bec5; font-size:0.85em; margin:5px 0;">${alert.details}</div>` : ''}
                                <div style="color:#78909c; font-size:0.75em; margin-top:8px;">🕐 ${alert.timestamp}</div>
                            </div>
                        `).join('');
                    }
                } catch (error) {
                    console.error('❌ Erreur historique:', error);
                }
            }
            
            async function loadBlacklist() {
                try {
                    const response = await fetch('/api/blacklist');
                    const data = await response.json();
                    const blacklist = data.blacklist || [];
                    
                    document.getElementById('blacklistCount').textContent = blacklist.length;
                    
                    if (blacklist.length === 0) {
                        document.getElementById('blacklistContainer').innerHTML = '<div class="empty-state"><p>Aucune IP</p></div>';
                        return;
                    }
                    
                    document.getElementById('blacklistContainer').innerHTML = blacklist.map(ip => `
                        <div class="blacklist-item">
                            <div class="blacklist-ip">🚫 ${ip}</div>
                            <button class="remove-btn" onclick="removeFromBlacklist('${ip}')">
                                ✖ RETIRER
                            </button>
                        </div>
                    `).join('');
                } catch (error) {
                    console.error('❌ Erreur blacklist:', error);
                }
            }
            
            async function addToBlacklist() {
                const input = document.getElementById('blacklistInput');
                const ip = input.value.trim();
                
                if (!ip) {
                    alert('❌ Entrer une IP');
                    return;
                }
                
                try {
                    const response = await fetch('/api/blacklist/add', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ ip: ip })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        input.value = '';
                        loadBlacklist();
                        alert('✅ IP ajoutée');
                    } else {
                        alert('❌ ' + data.message);
                    }
                } catch (error) {
                    alert('❌ Erreur: ' + error);
                }
            }
            
            async function removeFromBlacklist(ip) {
                if (!confirm(`Retirer ${ip} ?`)) return;
                
                try {
                    const response = await fetch('/api/blacklist/remove', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ ip: ip })
                    });
                    
                    if (response.ok) {
                        loadBlacklist();
                        alert('✅ IP retirée');
                    }
                } catch (error) {
                    alert('❌ Erreur: ' + error);
                }
            }
            
            async function loadDevices() {
                try {
                    const response = await fetch('/api/devices');
                    const data = await response.json();
                    const devices = data.devices || {};
                    
                    const deviceCount = Object.keys(devices).length;
                    document.getElementById('deviceCount').textContent = deviceCount;
                    
                    if (deviceCount === 0) {
                        document.getElementById('devicesContainer').innerHTML = '<div class="empty-state"><p>Aucun appareil</p></div>';
                        return;
                    }
                    
                    document.getElementById('devicesContainer').innerHTML = Object.entries(devices).map(([mac, info]) => {
                        const suspiciousPortsCount = (info.suspicious_ports || []).length;
                        const suspiciousBadge = suspiciousPortsCount > 0 ? 
                            `<div class="device-detail" style="color:#ff1744;"><strong>⚠️ Suspects:</strong> ${suspiciousPortsCount}</div>` : '';
                        
                        return `
                            <div class="device-item">
                                <div class="device-main">
                                    <div class="device-mac">📱 ${mac}</div>
                                    <div class="device-details">
                                        <div class="device-detail"><strong>IP:</strong> ${info.ips.join(', ')}</div>
                                        <div class="device-detail"><strong>Type:</strong> ${info.type}</div>
                                        <div class="device-detail"><strong>Ports:</strong> ${info.open_ports.length}</div>
                                        ${suspiciousBadge}
                                        <div class="device-detail"><strong>Vu:</strong> ${info.first_seen}</div>
                                    </div>
                                </div>
                            </div>
                        `;
                    }).join('');
                } catch (error) {
                    console.error('❌ Erreur devices:', error);
                }
            }
            
            function toggleHistory() {
                document.getElementById('historySidebar').classList.toggle('open');
                loadHistory();
            }
            
            document.getElementById('blacklistInput').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') addToBlacklist();
            });
            
            console.log('🚀 WiFi Monitor  - Détection Ports Suspects');
            
            updateStats();
            updateChart();
            updateCurrentAlerts();
            loadHistory();
            loadBlacklist();
            loadDevices();
            
            setInterval(updateStats, 5000);
            setInterval(updateChart, 5000);
            setInterval(updateCurrentAlerts, 5000);
            setInterval(loadDevices, 10000);
            setInterval(loadHistory, 30000);
            
            console.log('✅ Monitoring actif! Détection ports suspects (Backdoors, Trojans, Services vulnérables)');
        </script>
    </body>
    </html>
    """
    
    return html

if __name__ == '__main__':
    print("╔════════════════════════════════════════╗")
    print("║  🛡️  WiFi Monitor v6.2                 ║")
    print("║  Détection Ports Suspects              ║")
    print("║  http://192.168.1.247:5000             ║")
    print("╚════════════════════════════════════════╝\n")
    print("✅ Serveur démarré!")
    print("📡 Détections:")
    print("   - DDoS 🔥")
    print("   - Ports Suspects 🔍")
    print("     • Backdoors (31337, 12345, 6666...)")
    print("     • Trojans (SubSeven, NetBus...)")
    print("     • Exploits (Metasploit, ADB...)")
    print("     • DB exposées (MySQL, PostgreSQL...)")
    print("   - ARP Spoofing 🎭")
    print("   - MAC Spoofing 🔖")
    print("   - MITM Gateway 🔴")
    print("   - Deauth ⚡")
    print("\n⏱️  Expiration: 2 min")
    print("🔄 Refresh: 5s")
    print("\n🔍 En attente ESP8266...\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)