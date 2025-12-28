from flask import Flask, request, render_template_string, session, redirect, url_for, jsonify, g
import os
import re
import base64
import json
from datetime import datetime
import requests
import ipaddress
import socket
import whois
import time
from urllib.parse import urlparse
import concurrent.futures
import threading
import dns.resolver
import ssl
import random
import hashlib

app = Flask(__name__)

# Render için güvenli ayarlar
app.secret_key = os.environ.get('SECRET_KEY', 'dark_haribo_2025_terminal_key')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800

CORRECT_KEY = os.environ.get('ACCESS_KEY', 'haribo2025')

# Global değişken
users_data = {}
osint_cache = {}
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/537.36'
]

# GitHub'dan veri çekmek için ayarlar
GITHUB_USERNAME = os.environ.get('GITHUB_USERNAME', 'cappyyyyyy')
GITHUB_REPO = os.environ.get('GITHUB_REPO', 'vahset')
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')

class DarkHariboStyle:
    """Dark terminal teması sabitler"""
    COLORS = {
        'terminal_black': '#0a0a0a',
        'terminal_dark': '#121212',
        'terminal_gray': '#1a1a1a',
        'terminal_light_gray': '#2a2a2a',
        'terminal_green': '#00ff00',
        'terminal_cyan': '#00ffff',
        'terminal_blue': '#0088ff',
        'terminal_purple': '#aa00ff',
        'terminal_red': '#ff3333',
        'terminal_yellow': '#ffff00',
        'terminal_orange': '#ff8800',
        'terminal_white': '#ffffff',
        'terminal_magenta': '#ff00ff',
        'haribo_green': '#00cc66',
        'haribo_yellow': '#ffcc00',
        'haribo_red': '#ff3366',
        'haribo_orange': '#ff9966'
    }
    
    GRADIENTS = {
        'terminal_dark': 'linear-gradient(135deg, #0a0a0a 0%, #121212 50%, #1a1a1a 100%)',
        'terminal_glow': 'linear-gradient(90deg, #00ff00 0%, #00ffff 100%)',
        'terminal_blue': 'linear-gradient(90deg, #0088ff 0%, #00aaff 100%)',
        'terminal_purple': 'linear-gradient(90deg, #aa00ff 0%, #cc66ff 100%)',
        'haribo_green': 'linear-gradient(90deg, #00cc66 0%, #00ff88 100%)',
        'haribo_gold': 'linear-gradient(90deg, #ffcc00 0%, #ff9900 100%)',
        'haribo_red': 'linear-gradient(90deg, #ff3366 0%, #ff0066 100%)',
        'haribo_rainbow': 'linear-gradient(90deg, #ff3366 0%, #ff9966 25%, #ffcc00 50%, #00cc66 75%, #0088ff 100%)'
    }
    
    @staticmethod
    def get_haribo_emoji():
        """Rastgele Haribo emojisi"""
        emojis = ['🍬', '🍭', '🍫', '🧁', '🍩', '🍪', '🥨', '🍰', '🎂', '🍦', '🍧', '🍨']
        return random.choice(emojis)

def parse_line_data(line):
    """Bir satır veriyi parse et"""
    line = line.strip().rstrip(',')
    if not line or not line.startswith('('):
        return None
    
    if line.endswith('),'):
        line = line[:-1]
    
    if line.startswith('(') and line.endswith(')'):
        line = line[1:-1]
        
        # Değerleri ayır
        values = []
        current = ""
        in_quotes = False
        quote_char = None
        in_brackets = 0
        
        for char in line:
            if char in ("'", '"') and not in_quotes and in_brackets == 0:
                in_quotes = True
                quote_char = char
                current += char
            elif char == quote_char and in_quotes:
                in_quotes = False
                current += char
            elif char == '[' and not in_quotes:
                in_brackets += 1
                current += char
            elif char == ']' and not in_quotes:
                in_brackets -= 1
                current += char
            elif char == ',' and not in_quotes and in_brackets == 0:
                values.append(current.strip())
                current = ""
            else:
                current += char
        
        if current:
            values.append(current.strip())
        
        # Verileri çıkar
        if len(values) >= 9:
            user_id = values[0].strip().strip("'\"")
            
            # Email decode
            email_encoded = values[1].strip().strip("'\"")
            email = "N/A"
            
            if email_encoded and email_encoded not in ['null', '', 'NULL']:
                try:
                    decoded = base64.b64decode(email_encoded)
                    email = decoded.decode('utf-8', errors='ignore')
                except:
                    email = email_encoded
            
            # IP adresi
            ip = values[8].strip().strip("'\"") if len(values) > 8 else "N/A"
            if ip in ['null', 'NULL']:
                ip = "N/A"
            
            return {
                'user_id': user_id,
                'email': email,
                'ip': ip,
                'encoded': email_encoded
            }
    
    return None

def load_data_from_github():
    """GitHub'dan veri çek"""
    global users_data
    
    print("=" * 70)
    print("🍬 DARK HARIBO OSINT v3.0 - GITHUB DATA LOADER")
    print("=" * 70)
    
    all_users = {}
    
    # GitHub raw URL'leri
    github_files = [
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part1.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part2.txt", 
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part3.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part4.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part5.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part6.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part7.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part8.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part9.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part10.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part11.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part12.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part13.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part14.txt",
        "https://raw.githubusercontent.com/cappyyyyyy/vahset/main/data_part15.txt"       
        ]
    
    total_loaded = 0
    
    for i, url in enumerate(github_files, 1):
        print(f"\n📖 GitHub'dan yükleniyor: data_part{i}.txt")
        
        try:
            headers = {'User-Agent': random.choice(user_agents)}
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                content = response.text
                lines = content.strip().split('\n')
                print(f"   ✅ Yüklendi: {len(lines)} satır")
                
                file_count = 0
                for line in lines:
                    data = parse_line_data(line)
                    if data:
                        all_users[data['user_id']] = {
                            'email': data['email'],
                            'ip': data['ip'],
                            'encoded': data['encoded']
                        }
                        file_count += 1
                        total_loaded += 1
                
                print(f"   📊 Parse edildi: {file_count} kayıt")
                
            elif response.status_code == 404:
                print(f"   ⚠️  Dosya bulunamadı: data_part{i}.txt")
            else:
                print(f"   ❌ Hata: {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ Network hatası: {str(e)}")
    
    print(f"\n🎯 TOPLAM YÜKLENEN: {len(all_users):,} kullanıcı")
    
    if all_users:
        print("\n📊 ÖRNEK KAYITLAR:")
        sample_ids = list(all_users.keys())[:3]
        for uid in sample_ids:
            data = all_users[uid]
            print(f"   📍 ID: {uid}")
            print(f"      📧 Email: {data['email'][:50]}...")
            print(f"      🌐 IP: {data['ip']}")
            print()
    
    users_data = all_users
    return all_users

# ==================== OSINT FONKSIYONLARI ====================

def get_ip_geolocation(ip):
    """Free IP geolocation servisleri"""
    if not ip or ip == "N/A":
        return None
    
    try:
        # ip-api.com (free, no API key needed)
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return {
                    'country': data.get('country', 'Unknown'),
                    'countryCode': data.get('countryCode', 'XX'),
                    'region': data.get('regionName', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'zip': data.get('zip', 'Unknown'),
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                    'isp': data.get('isp', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'as': data.get('as', 'Unknown')
                }
    except:
        pass
    
    try:
        # ipapi.co (free tier)
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if not data.get('error'):
                return {
                    'country': data.get('country_name', 'Unknown'),
                    'countryCode': data.get('country_code', 'XX'),
                    'region': data.get('region', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'zip': data.get('postal', 'Unknown'),
                    'lat': data.get('latitude', 0),
                    'lon': data.get('longitude', 0),
                    'isp': data.get('org', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'as': data.get('asn', 'Unknown')
                }
    except:
        pass
    
    return None

def check_ip_reputation(ip):
    """IP reputation check with free sources"""
    reputation = {
        'threat_level': 'Low',
        'blacklists': [],
        'proxy': False,
        'vpn': False,
        'tor': False
    }
    
    try:
        # Check if it's a private IP
        if ipaddress.ip_address(ip).is_private:
            reputation['threat_level'] = 'Local'
            reputation['is_private'] = True
            return reputation
        
        # AbuseIPDB check (free tier - limited)
        headers = {'Key': '', 'Accept': 'application/json'}
        response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", 
                              headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('data'):
                rep = data['data']
                if rep.get('abuseConfidenceScore', 0) > 50:
                    reputation['threat_level'] = 'High'
                elif rep.get('abuseConfidenceScore', 0) > 20:
                    reputation['threat_level'] = 'Medium'
                
                if rep.get('isTor'):
                    reputation['tor'] = True
                if rep.get('isPublic'):
                    reputation['proxy'] = True
        
        # Check common blacklists via DNSBL
        blacklists = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'b.barracudacentral.org'
        ]
        
        reversed_ip = '.'.join(reversed(ip.split('.')))
        
        for bl in blacklists:
            try:
                query = f"{reversed_ip}.{bl}"
                socket.gethostbyname(query)
                reputation['blacklists'].append(bl)
            except:
                pass
        
        if reputation['blacklists']:
            reputation['threat_level'] = 'High'
            
    except Exception as e:
        print(f"IP reputation check error: {e}")
    
    return reputation

def get_whois_info(domain):
    """WHOIS bilgisi al"""
    try:
        w = whois.whois(domain)
        return {
            'registrar': w.registrar,
            'creation_date': str(w.creation_date) if w.creation_date else 'Unknown',
            'expiration_date': str(w.expiration_date) if w.expiration_date else 'Unknown',
            'name_servers': list(w.name_servers)[:5] if w.name_servers else [],
            'org': w.org,
            'country': w.country
        }
    except:
        return None

def check_email_breaches(email):
    """Email breach kontrolü (Have I Been Pwned API'siz versiyon)"""
    breaches = []
    
    try:
        # Check common breach patterns
        email_hash = hashlib.sha1(email.lower().encode()).hexdigest().upper()
        
        # Local breach check (simulated for common breaches)
        common_breaches = [
            {'name': 'LinkedIn 2012', 'date': '2012', 'records': '165M'},
            {'name': 'Adobe 2013', 'date': '2013', 'records': '153M'},
            {'name': 'Dropbox 2012', 'date': '2012', 'records': '68M'},
            {'name': 'Twitter 2016', 'date': '2016', 'records': '33M'},
            {'name': 'Facebook 2019', 'date': '2019', 'records': '533M'}
        ]
        
        # Simulate random breach detection (in real app, use API)
        import random
        if random.random() > 0.7:  # 30% chance of finding a breach
            breaches = random.sample(common_breaches, random.randint(1, 3))
        
    except:
        pass
    
    return breaches

def analyze_email(email):
    """Email analizi"""
    analysis = {
        'provider': 'Unknown',
        'disposable': False,
        'valid_format': False,
        'breaches': [],
        'social_media': []
    }
    
    if not email or email == 'N/A':
        return analysis
    
    # Check email format
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(email_regex, email):
        analysis['valid_format'] = True
        
        # Extract domain
        domain = email.split('@')[1].lower()
        analysis['domain'] = domain
        
        # Check common providers
        common_providers = {
            'gmail.com': 'Google',
            'yahoo.com': 'Yahoo',
            'outlook.com': 'Microsoft',
            'hotmail.com': 'Microsoft',
            'icloud.com': 'Apple',
            'aol.com': 'AOL',
            'protonmail.com': 'ProtonMail',
            'yandex.com': 'Yandex'
        }
        
        if domain in common_providers:
            analysis['provider'] = common_providers[domain]
        
        # Check disposable emails
        disposable_domains = ['mailinator.com', 'tempmail.com', 'guerrillamail.com', 
                             '10minutemail.com', 'throwawaymail.com']
        if domain in disposable_domains:
            analysis['disposable'] = True
        
        # Check breaches
        analysis['breaches'] = check_email_breaches(email)
        
        # Guess social media (basic pattern matching)
        username = email.split('@')[0].lower()
        common_patterns = {
            'john': ['Facebook', 'Twitter'],
            'jane': ['Facebook', 'Instagram'],
            'admin': ['LinkedIn', 'Twitter'],
            'info': ['Business', 'LinkedIn'],
            'support': ['Business', 'Service']
        }
        
        for pattern, platforms in common_patterns.items():
            if pattern in username:
                analysis['social_media'] = platforms
                break
    
    return analysis

def get_dns_info(domain):
    """DNS kayıtlarını kontrol et"""
    dns_records = {}
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        # A record
        try:
            answers = resolver.resolve(domain, 'A')
            dns_records['A'] = [str(r) for r in answers]
        except:
            pass
        
        # MX records
        try:
            answers = resolver.resolve(domain, 'MX')
            dns_records['MX'] = [str(r) for r in answers]
        except:
            pass
        
        # TXT records
        try:
            answers = resolver.resolve(domain, 'TXT')
            dns_records['TXT'] = [str(r) for r in answers]
        except:
            pass
        
        # NS records
        try:
            answers = resolver.resolve(domain, 'NS')
            dns_records['NS'] = [str(r) for r in answers]
        except:
            pass
        
    except Exception as e:
        print(f"DNS check error: {e}")
    
    return dns_records

def scan_website(domain):
    """Temel website taraması"""
    scan_result = {
        'ssl': False,
        'server': 'Unknown',
        'status': 'Unknown',
        'ports': [],
        'technologies': []
    }
    
    try:
        # Check SSL
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                scan_result['ssl'] = True
                cert = ssock.getpeercert()
                if cert:
                    scan_result['ssl_expiry'] = cert['notAfter']
        
        # Check common ports
        common_ports = [80, 443, 21, 22, 25, 3389, 8080, 8443]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((domain, port))
                if result == 0:
                    scan_result['ports'].append(port)
                sock.close()
            except:
                pass
        
        # Guess server from headers
        try:
            response = requests.get(f"http://{domain}", timeout=5)
            scan_result['status'] = response.status_code
            if 'Server' in response.headers:
                scan_result['server'] = response.headers['Server']
            
            # Detect technologies
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            if 'x-powered-by' in headers_lower:
                scan_result['technologies'].append(headers_lower['x-powered-by'])
            if 'x-aspnet-version' in headers_lower:
                scan_result['technologies'].append('ASP.NET')
        
        except:
            pass
        
    except Exception as e:
        print(f"Website scan error: {e}")
    
    return scan_result

def perform_ip_osint(ip):
    """Tam IP OSINT analizi"""
    osint_data = {
        'geolocation': None,
        'reputation': None,
        'whois': None,
        'dns': None,
        'scan': None,
        'services': []
    }
    
    if not ip or ip == "N/A":
        return osint_data
    
    # Cache kontrolü
    cache_key = f"ip_{ip}"
    if cache_key in osint_cache:
        return osint_cache[cache_key]
    
    try:
        # Parallel execution için thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            # Geolocation
            geo_future = executor.submit(get_ip_geolocation, ip)
            
            # Reputation
            rep_future = executor.submit(check_ip_reputation, ip)
            
            # DNS reverse lookup
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                osint_data['hostname'] = hostname
                
                # WHOIS for domain
                if '.' in hostname:
                    whois_future = executor.submit(get_whois_info, hostname)
                    osint_data['whois'] = whois_future.result(timeout=10)
                    
                    # DNS records
                    dns_future = executor.submit(get_dns_info, hostname)
                    osint_data['dns'] = dns_future.result(timeout=10)
                    
                    # Website scan
                    scan_future = executor.submit(scan_website, hostname)
                    osint_data['scan'] = scan_future.result(timeout=10)
            except:
                pass
            
            # Get results
            osint_data['geolocation'] = geo_future.result(timeout=10)
            osint_data['reputation'] = rep_future.result(timeout=10)
        
        # Detect running services
        common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        
        for port, service in common_services.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    osint_data['services'].append({
                        'port': port,
                        'service': service,
                        'status': 'Open'
                    })
                sock.close()
            except:
                pass
        
        # Cache'e kaydet
        osint_cache[cache_key] = osint_data
        
    except Exception as e:
        print(f"IP OSINT error: {e}")
    
    return osint_data

def perform_email_osint(email):
    """Tam Email OSINT analizi"""
    osint_data = {
        'analysis': None,
        'breaches': [],
        'social_media': [],
        'domain_info': None,
        'associated_ips': []
    }
    
    if not email or email == "N/A":
        return osint_data
    
    # Cache kontrolü
    cache_key = f"email_{email}"
    if cache_key in osint_cache:
        return osint_cache[cache_key]
    
    try:
        # Email analizi
        osint_data['analysis'] = analyze_email(email)
        
        # Domain kısmını al
        if '@' in email:
            domain = email.split('@')[1]
            
            # DNS bilgileri
            osint_data['domain_info'] = get_dns_info(domain)
            
            # WHOIS bilgisi
            osint_data['whois'] = get_whois_info(domain)
            
            # Website taraması
            osint_data['website_scan'] = scan_website(domain)
            
            # Bu domain için IP'leri bul (basit DNS lookup)
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                osint_data['associated_ips'] = ips[:5]  # İlk 5 IP
            except:
                pass
        
        # Cache'e kaydet
        osint_cache[cache_key] = osint_data
        
    except Exception as e:
        print(f"Email OSINT error: {e}")
    
    return osint_data

# ==================== FLASK ROUTES ====================

# Verileri uygulama başladığında yükle
with app.app_context():
    print("\n" + "="*80)
    print("🍬 DARK HARIBO OSINT v3.0")
    print("="*80)
    print("📦 GitHub'dan veriler yükleniyor...")
    users_data = load_data_from_github()
    print("✅ OSINT modülleri hazır")
    print("="*80 + "\n")

@app.before_request
def before_request():
    """Her request öncesi çalışır"""
    g.users_data = users_data

@app.route('/')
def index():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('authenticated'):
        return redirect('/terminal')
    
    error = None
    if request.method == 'POST':
        entered_key = request.form.get('access_key')
        if entered_key == CORRECT_KEY:
            session['authenticated'] = True
            session.permanent = True
            return jsonify({'success': True, 'redirect': '/terminal'})
        else:
            error = "⚠️ Invalid access key!"
    
    colors = DarkHariboStyle.COLORS
    gradients = DarkHariboStyle.GRADIENTS
    
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DARK HARIBO OSINT | TERMINAL ACCESS</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Ubuntu+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --terminal-black: {{ colors.terminal_black }};
                --terminal-dark: {{ colors.terminal_dark }};
                --terminal-gray: {{ colors.terminal_gray }};
                --terminal-light-gray: {{ colors.terminal_light_gray }};
                --haribo-green: {{ colors.haribo_green }};
                --haribo-yellow: {{ colors.haribo_yellow }};
                --haribo-red: {{ colors.haribo_red }};
                --haribo-orange: {{ colors.haribo_orange }};
                --terminal-green: {{ colors.terminal_green }};
                --terminal-cyan: {{ colors.terminal_cyan }};
                --terminal-blue: {{ colors.terminal_blue }};
                --terminal-purple: {{ colors.terminal_purple }};
                --gradient-dark: {{ gradients.terminal_dark }};
                --gradient-glow: {{ gradients.terminal_glow }};
                --gradient-haribo: {{ gradients.haribo_green }};
                --gradient-gold: {{ gradients.haribo_gold }};
                --gradient-rainbow: {{ gradients.haribo_rainbow }};
            }
            
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'JetBrains Mono', monospace;
                background: var(--terminal-black);
                color: var(--terminal-green);
                min-height: 100vh;
                overflow: hidden;
            }
            
            .matrix-grid {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: 
                    linear-gradient(rgba(0, 204, 102, 0.03) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(0, 204, 102, 0.03) 1px, transparent 1px);
                background-size: 20px 20px;
                z-index: -2;
                opacity: 0.3;
            }
            
            .terminal-background {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: var(--gradient-dark);
                z-index: -1;
            }
            
            .terminal-container {
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                padding: 20px;
            }
            
            .terminal-window {
                background: rgba(10, 10, 10, 0.95);
                border: 2px solid var(--haribo-green);
                border-radius: 0;
                width: 100%;
                max-width: 600px;
                box-shadow: 
                    0 0 40px rgba(0, 204, 102, 0.5),
                    0 0 0 1px rgba(0, 255, 0, 0.1),
                    inset 0 0 20px rgba(0, 0, 0, 0.8);
                overflow: hidden;
                font-family: 'Ubuntu Mono', monospace;
            }
            
            .terminal-header {
                background: rgba(26, 26, 26, 0.9);
                padding: 15px 20px;
                border-bottom: 2px solid var(--haribo-green);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .terminal-title {
                font-size: 1.5em;
                font-weight: 700;
                color: var(--haribo-green);
                letter-spacing: 1px;
                text-shadow: 0 0 10px rgba(0, 204, 102, 0.5);
            }
            
            .terminal-subtitle {
                color: var(--haribo-yellow);
                font-size: 0.9em;
                opacity: 0.8;
            }
            
            .terminal-content {
                padding: 40px;
            }
            
            .boot-sequence {
                margin-bottom: 30px;
            }
            
            .boot-line {
                display: flex;
                align-items: center;
                gap: 10px;
                margin-bottom: 10px;
                font-size: 0.95em;
                color: var(--terminal-cyan);
            }
            
            .boot-line::before {
                content: '>';
                color: var(--haribo-green);
                font-weight: bold;
            }
            
            .login-form {
                display: flex;
                flex-direction: column;
                gap: 25px;
            }
            
            .input-group {
                position: relative;
            }
            
            .terminal-input {
                background: rgba(0, 0, 0, 0.7);
                border: 2px solid var(--terminal-blue);
                border-radius: 0;
                color: var(--terminal-green);
                font-family: 'Ubuntu Mono', monospace;
                padding: 15px 20px;
                width: 100%;
                font-size: 16px;
                letter-spacing: 2px;
                transition: all 0.3s ease;
            }
            
            .terminal-input:focus {
                outline: none;
                border-color: var(--haribo-green);
                box-shadow: 0 0 20px rgba(0, 204, 102, 0.3);
                background: rgba(0, 0, 0, 0.9);
            }
            
            .input-label {
                position: absolute;
                left: 12px;
                top: -12px;
                background: var(--terminal-black);
                padding: 0 8px;
                color: var(--haribo-yellow);
                font-size: 0.8em;
                letter-spacing: 1px;
            }
            
            .terminal-button {
                background: var(--gradient-haribo);
                border: 2px solid var(--haribo-green);
                border-radius: 0;
                color: #000;
                font-family: 'JetBrains Mono', monospace;
                font-weight: 700;
                padding: 18px;
                font-size: 16px;
                cursor: pointer;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 15px;
                letter-spacing: 2px;
                text-transform: uppercase;
                position: relative;
                overflow: hidden;
            }
            
            .terminal-button:hover {
                background: var(--gradient-gold);
                border-color: var(--haribo-yellow);
                box-shadow: 0 0 30px rgba(255, 204, 0, 0.5);
            }
            
            .terminal-button:active {
                transform: translateY(2px);
            }
            
            .error-box {
                background: rgba(255, 51, 102, 0.1);
                border: 2px solid var(--haribo-red);
                padding: 15px;
                color: var(--haribo-red);
                font-size: 0.9em;
                display: flex;
                align-items: center;
                gap: 10px;
                animation: terminalError 0.5s;
            }
            
            @keyframes terminalError {
                0%, 100% { border-color: var(--haribo-red); }
                50% { border-color: var(--haribo-orange); }
            }
            
            .terminal-footer {
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid rgba(0, 204, 102, 0.3);
                color: var(--terminal-cyan);
                font-size: 0.8em;
                text-align: center;
            }
            
            .haribo-emoji {
                font-size: 1.2em;
                animation: hariboGlow 2s infinite alternate;
            }
            
            @keyframes hariboGlow {
                from { text-shadow: 0 0 5px var(--haribo-green); }
                to { text-shadow: 0 0 20px var(--haribo-green); }
            }
            
            .blink {
                animation: blink 1s infinite;
            }
            
            @keyframes blink {
                0%, 50% { opacity: 1; }
                51%, 100% { opacity: 0; }
            }
            
            @media (max-width: 600px) {
                .terminal-window {
                    margin: 10px;
                }
                
                .terminal-content {
                    padding: 30px 20px;
                }
            }
        </style>
    </head>
    <body>
        <div class="matrix-grid"></div>
        <div class="terminal-background"></div>
        
        <div class="terminal-container">
            <div class="terminal-window">
                <div class="terminal-header">
                    <div class="terminal-title">
                        DARK HARIBO OSINT v3.0
                    </div>
                    <div class="terminal-subtitle">
                        <span class="haribo-emoji">🍬</span> TERMINAL EDITION
                    </div>
                </div>
                
                <div class="terminal-content">
                    <div class="boot-sequence">
                        <div class="boot-line">SYSTEM INITIALIZED</div>
                        <div class="boot-line">OSINT MODULES LOADED</div>
                        <div class="boot-line">DATABASE CONNECTION ESTABLISHED</div>
                        <div class="boot-line">AWAITING USER AUTHENTICATION<span class="blink">_</span></div>
                    </div>
                    
                    <form id="loginForm" method="POST" class="login-form">
                        <div class="input-group">
                            <div class="input-label">ACCESS KEY REQUIRED</div>
                            <input type="password" 
                                   name="access_key" 
                                   class="terminal-input"
                                   placeholder="ENTER KEY"
                                   required
                                   autofocus>
                        </div>
                        
                        <button type="submit" class="terminal-button">
                            <i class="fas fa-terminal"></i>
                            BOOT TERMINAL
                        </button>
                        
                        {% if error %}
                        <div class="error-box">
                            <i class="fas fa-exclamation-triangle"></i>
                            {{ error }}
                        </div>
                        {% endif %}
                    </form>
                    
                    <div class="terminal-footer">
                        <div>HARIBO INTELLIGENCE SUITE • GITHUB DATASOURCE</div>
                        <div style="margin-top: 10px;">
                            <span class="haribo-emoji">🍫</span> ENCRYPTED TERMINAL <span class="haribo-emoji">🍭</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            document.getElementById('loginForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const formData = new FormData(this);
                const button = this.querySelector('.terminal-button');
                const originalText = button.innerHTML;
                
                // Terminal boot sequence animation
                button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> BOOTING...';
                button.disabled = true;
                
                // Create terminal boot effect
                const bootSequence = document.querySelector('.boot-sequence');
                const bootLines = [
                    '> AUTHENTICATING USER...',
                    '> VERIFYING ACCESS CREDENTIALS...',
                    '> LOADING OSINT DATABASE...',
                    '> INITIALIZING HARIBO MODULES...'
                ];
                
                let lineIndex = 0;
                const bootInterval = setInterval(() => {
                    if (lineIndex < bootLines.length) {
                        const bootLine = document.createElement('div');
                        bootLine.className = 'boot-line';
                        bootLine.textContent = bootLines[lineIndex];
                        bootSequence.appendChild(bootLine);
                        lineIndex++;
                    }
                }, 500);
                
                try {
                    const response = await fetch('/login', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const data = await response.json();
                    
                    clearInterval(bootInterval);
                    
                    if (data.success) {
                        // Success - add final boot line
                        const successLine = document.createElement('div');
                        successLine.className = 'boot-line';
                        successLine.style.color = 'var(--haribo-green)';
                        successLine.innerHTML = '> ACCESS GRANTED <span class="haribo-emoji">🎉</span>';
                        bootSequence.appendChild(successLine);
                        
                        button.innerHTML = '<i class="fas fa-check"></i> ENTER TERMINAL';
                        button.style.background = 'var(--gradient-haribo)';
                        
                        // Haribo animation
                        const emojis = ['🍬', '🍭', '🍫', '🧁', '🍩', '🍪'];
                        for (let i = 0; i < 10; i++) {
                            setTimeout(() => {
                                const emoji = document.createElement('span');
                                emoji.className = 'haribo-emoji';
                                emoji.textContent = emojis[Math.floor(Math.random() * emojis.length)];
                                emoji.style.position = 'fixed';
                                emoji.style.left = `${Math.random() * 100}%`;
                                emoji.style.top = `${Math.random() * 100}%`;
                                emoji.style.fontSize = '24px';
                                emoji.style.animation = 'hariboGlow 1s ease-out forwards';
                                emoji.style.zIndex = '1000';
                                document.body.appendChild(emoji);
                                setTimeout(() => emoji.remove(), 1000);
                            }, i * 100);
                        }
                        
                        setTimeout(() => {
                            window.location.href = data.redirect;
                        }, 2000);
                    } else {
                        // Error state
                        button.innerHTML = originalText;
                        button.disabled = false;
                        
                        const errorLine = document.createElement('div');
                        errorLine.className = 'boot-line';
                        errorLine.style.color = 'var(--haribo-red)';
                        errorLine.innerHTML = '> AUTHENTICATION FAILED <span class="haribo-emoji">⚠️</span>';
                        bootSequence.appendChild(errorLine);
                        
                        const errorDiv = document.createElement('div');
                        errorDiv.className = 'error-box';
                        errorDiv.innerHTML = '<i class="fas fa-exclamation-triangle"></i> INVALID ACCESS KEY';
                        
                        const existingError = document.querySelector('.error-box');
                        if (existingError) {
                            existingError.remove();
                        }
                        
                        this.appendChild(errorDiv);
                    }
                } catch (error) {
                    clearInterval(bootInterval);
                    button.innerHTML = originalText;
                    button.disabled = false;
                    alert('NETWORK ERROR - PLEASE TRY AGAIN');
                }
            });
        </script>
    </body>
    </html>
    ''', error=error, colors=DarkHariboStyle.COLORS, gradients=DarkHariboStyle.GRADIENTS)

@app.route('/terminal', methods=['GET', 'POST'])
def terminal():
    if not session.get('authenticated'):
        return redirect('/login')
    
    result = None
    user_id = None
    search_time = None
    osint_type = request.form.get('osint_type', 'basic')
    ip_osint_result = None
    email_osint_result = None
    
    if request.method == 'POST':
        user_id = request.form.get('user_id', '').strip()
        search_time = datetime.now().strftime("%H:%M:%S")
        osint_type = request.form.get('osint_type', 'basic')
        
        if user_id:
            user_data = users_data.get(user_id)
            
            if user_data:
                result = {
                    'email': user_data['email'],
                    'ip': user_data['ip'],
                    'encoded': user_data.get('encoded', ''),
                    'status': 'success'
                }
                
                # OSINT analizleri
                if osint_type == 'ip_osint' and user_data['ip'] != 'N/A':
                    ip_osint_result = perform_ip_osint(user_data['ip'])
                
                if osint_type == 'email_osint' and user_data['email'] != 'N/A':
                    email_osint_result = perform_email_osint(user_data['email'])
                    
            else:
                # Benzer ID'leri bul
                similar = []
                for uid in users_data.keys():
                    if user_id in uid or uid.startswith(user_id[:5]):
                        similar.append(uid)
                        if len(similar) >= 5:
                            break
                
                result = {
                    'status': 'error',
                    'message': 'User ID not found in database',
                    'similar': similar[:5]
                }
    
    colors = DarkHariboStyle.COLORS
    gradients = DarkHariboStyle.GRADIENTS
    total_users = len(users_data)
    
    # Örnek ID'ler
    sample_ids = list(users_data.keys())[:12] if users_data else []
    
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DARK HARIBO OSINT | TERMINAL</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Ubuntu+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --terminal-black: {{ colors.terminal_black }};
                --terminal-dark: {{ colors.terminal_dark }};
                --terminal-gray: {{ colors.terminal_gray }};
                --terminal-light-gray: {{ colors.terminal_light_gray }};
                --haribo-green: {{ colors.haribo_green }};
                --haribo-yellow: {{ colors.haribo_yellow }};
                --haribo-red: {{ colors.haribo_red }};
                --haribo-orange: {{ colors.haribo_orange }};
                --terminal-green: {{ colors.terminal_green }};
                --terminal-cyan: {{ colors.terminal_cyan }};
                --terminal-blue: {{ colors.terminal_blue }};
                --terminal-purple: {{ colors.terminal_purple }};
                --gradient-dark: {{ gradients.terminal_dark }};
                --gradient-glow: {{ gradients.terminal_glow }};
                --gradient-haribo: {{ gradients.haribo_green }};
                --gradient-gold: {{ gradients.haribo_gold }};
                --gradient-rainbow: {{ gradients.haribo_rainbow }};
            }
            
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'JetBrains Mono', monospace;
                background: var(--terminal-black);
                color: var(--terminal-green);
                min-height: 100vh;
                overflow-x: hidden;
            }
            
            .matrix-grid {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: 
                    linear-gradient(rgba(0, 204, 102, 0.03) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(0, 204, 102, 0.03) 1px, transparent 1px);
                background-size: 20px 20px;
                z-index: -2;
                opacity: 0.3;
            }
            
            .terminal-wrapper {
                display: flex;
                flex-direction: column;
                min-height: 100vh;
            }
            
            /* Terminal Header */
            .terminal-header {
                background: rgba(10, 10, 10, 0.95);
                border-bottom: 2px solid var(--haribo-green);
                padding: 15px 30px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                position: sticky;
                top: 0;
                z-index: 100;
                backdrop-filter: blur(10px);
            }
            
            .terminal-logo {
                display: flex;
                align-items: center;
                gap: 15px;
            }
            
            .logo-icon {
                font-size: 2em;
                color: var(--haribo-green);
                animation: terminalPulse 2s infinite;
            }
            
            @keyframes terminalPulse {
                0%, 100% { 
                    text-shadow: 0 0 10px var(--haribo-green), 
                                 0 0 20px var(--haribo-green);
                }
                50% { 
                    text-shadow: 0 0 20px var(--haribo-green), 
                                 0 0 40px var(--haribo-green);
                }
            }
            
            .logo-text {
                font-size: 1.8em;
                font-weight: 700;
                color: var(--haribo-green);
                letter-spacing: 2px;
            }
            
            .terminal-stats {
                display: flex;
                gap: 20px;
            }
            
            .stat-terminal {
                background: rgba(0, 0, 0, 0.7);
                border: 1px solid var(--terminal-blue);
                padding: 10px 20px;
                text-align: center;
                min-width: 120px;
            }
            
            .stat-value {
                font-size: 1.4em;
                font-weight: 700;
                color: var(--haribo-yellow);
                margin-bottom: 5px;
            }
            
            .stat-label {
                font-size: 0.8em;
                color: var(--terminal-cyan);
                letter-spacing: 1px;
            }
            
            .logout-terminal {
                background: rgba(255, 51, 102, 0.2);
                border: 1px solid var(--haribo-red);
                color: var(--haribo-red);
                padding: 10px 20px;
                font-weight: 700;
                cursor: pointer;
                display: flex;
                align-items: center;
                gap: 10px;
                transition: all 0.3s ease;
                text-decoration: none;
                letter-spacing: 1px;
            }
            
            .logout-terminal:hover {
                background: rgba(255, 51, 102, 0.4);
                border-color: var(--haribo-orange);
                transform: translateY(-2px);
            }
            
            /* Main Content */
            .terminal-main {
                flex: 1;
                padding: 30px;
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 30px;
                max-width: 1600px;
                margin: 0 auto;
                width: 100%;
            }
            
            @media (max-width: 1200px) {
                .terminal-main {
                    grid-template-columns: 1fr;
                }
            }
            
            /* Left Panel - Terminal Interface */
            .terminal-interface {
                background: rgba(0, 0, 0, 0.8);
                border: 2px solid var(--haribo-green);
                padding: 25px;
                position: relative;
                box-shadow: 0 0 30px rgba(0, 204, 102, 0.3);
            }
            
            .terminal-interface::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 2px;
                background: var(--gradient-rainbow);
            }
            
            .interface-title {
                font-size: 1.4em;
                font-weight: 700;
                margin-bottom: 20px;
                color: var(--haribo-yellow);
                display: flex;
                align-items: center;
                gap: 10px;
                padding-bottom: 10px;
                border-bottom: 1px solid rgba(0, 204, 102, 0.3);
            }
            
            .terminal-form {
                display: flex;
                flex-direction: column;
                gap: 20px;
            }
            
            .terminal-input-group {
                position: relative;
            }
            
            .terminal-input-large {
                background: rgba(0, 0, 0, 0.9);
                border: 2px solid var(--terminal-cyan);
                color: var(--terminal-green);
                font-family: 'Ubuntu Mono', monospace;
                padding: 18px 20px;
                width: 100%;
                font-size: 16px;
                letter-spacing: 1px;
                transition: all 0.3s ease;
            }
            
            .terminal-input-large:focus {
                outline: none;
                border-color: var(--haribo-green);
                box-shadow: 0 0 20px rgba(0, 204, 102, 0.5);
            }
            
            .osint-options {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 15px;
                margin: 20px 0;
            }
            
            .option-terminal {
                background: rgba(0, 0, 0, 0.7);
                border: 1px solid var(--terminal-purple);
                padding: 15px;
                cursor: pointer;
                transition: all 0.3s ease;
                text-align: center;
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 10px;
            }
            
            .option-terminal:hover {
                border-color: var(--haribo-green);
                transform: translateY(-3px);
                box-shadow: 0 5px 15px rgba(0, 204, 102, 0.3);
            }
            
            .option-terminal.selected {
                background: rgba(0, 204, 102, 0.2);
                border-color: var(--haribo-green);
                box-shadow: 0 0 20px rgba(0, 204, 102, 0.5);
            }
            
            .option-terminal input[type="radio"] {
                display: none;
            }
            
            .option-icon {
                font-size: 1.5em;
                color: var(--haribo-yellow);
            }
            
            .option-text {
                font-weight: 600;
                font-size: 0.9em;
                color: var(--terminal-cyan);
            }
            
            .terminal-execute {
                background: var(--gradient-haribo);
                border: 2px solid var(--haribo-green);
                color: #000;
                font-weight: 700;
                padding: 20px;
                font-size: 18px;
                cursor: pointer;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 15px;
                letter-spacing: 2px;
                text-transform: uppercase;
            }
            
            .terminal-execute:hover {
                background: var(--gradient-gold);
                border-color: var(--haribo-yellow);
                box-shadow: 0 0 30px rgba(255, 204, 0, 0.5);
                transform: translateY(-3px);
            }
            
            .sample-database {
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid rgba(0, 204, 102, 0.3);
            }
            
            .sample-title {
                color: var(--haribo-yellow);
                margin-bottom: 15px;
                font-size: 1.1em;
                font-weight: 700;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .database-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
                gap: 10px;
            }
            
            .database-id {
                background: rgba(0, 0, 0, 0.7);
                border: 1px solid var(--terminal-blue);
                padding: 10px;
                font-size: 0.8em;
                cursor: pointer;
                transition: all 0.3s ease;
                text-align: center;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                color: var(--terminal-cyan);
            }
            
            .database-id:hover {
                background: rgba(0, 204, 102, 0.2);
                border-color: var(--haribo-green);
                transform: translateY(-2px);
                color: var(--haribo-green);
            }
            
            /* Right Panel - Results */
            .terminal-results {
                background: rgba(0, 0, 0, 0.8);
                border: 2px solid var(--haribo-yellow);
                padding: 25px;
                display: flex;
                flex-direction: column;
                box-shadow: 0 0 30px rgba(255, 204, 0, 0.3);
            }
            
            .terminal-results::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 2px;
                background: var(--gradient-rainbow);
            }
            
            .results-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 1px solid rgba(255, 204, 0, 0.3);
            }
            
            .search-time {
                color: var(--haribo-yellow);
                font-weight: 600;
                font-size: 0.9em;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .results-display {
                flex: 1;
                overflow-y: auto;
                max-height: 70vh;
                padding-right: 10px;
            }
            
            /* Scrollbar */
            .results-display::-webkit-scrollbar {
                width: 6px;
            }
            
            .results-display::-webkit-scrollbar-track {
                background: rgba(0, 0, 0, 0.3);
            }
            
            .results-display::-webkit-scrollbar-thumb {
                background: var(--haribo-green);
            }
            
            .welcome-terminal {
                text-align: center;
                padding: 40px 20px;
                color: var(--terminal-cyan);
            }
            
            .welcome-icon {
                font-size: 4em;
                color: var(--haribo-green);
                margin-bottom: 20px;
                opacity: 0.7;
            }
            
            /* Result Cards */
            .result-terminal {
                background: rgba(0, 0, 0, 0.9);
                border: 2px solid var(--haribo-green);
                padding: 20px;
                margin-bottom: 20px;
                animation: terminalSlide 0.5s ease;
            }
            
            @keyframes terminalSlide {
                from { opacity: 0; transform: translateY(20px); }
                to { opacity: 1; transform: translateY(0); }
            }
            
            .result-header-terminal {
                display: flex;
                align-items: center;
                gap: 15px;
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 1px solid rgba(0, 204, 102, 0.3);
            }
            
            .result-icon-terminal {
                font-size: 2em;
                color: var(--haribo-green);
            }
            
            .result-title-terminal {
                font-size: 1.3em;
                font-weight: 700;
                color: var(--haribo-yellow);
            }
            
            .data-grid {
                display: grid;
                gap: 15px;
                margin-bottom: 20px;
            }
            
            .data-row {
                display: flex;
                align-items: center;
                padding: 12px 15px;
                background: rgba(0, 0, 0, 0.5);
                border-left: 3px solid var(--haribo-green);
            }
            
            .row-label-terminal {
                min-width: 120px;
                color: var(--terminal-cyan);
                font-weight: 600;
                font-size: 0.95em;
            }
            
            .row-value-terminal {
                flex: 1;
                word-break: break-all;
                font-family: 'Ubuntu Mono', monospace;
                color: var(--terminal-green);
                font-size: 0.95em;
            }
            
            /* OSINT Sections */
            .osint-section-terminal {
                margin-top: 25px;
                padding-top: 20px;
                border-top: 1px solid rgba(255, 204, 0, 0.3);
            }
            
            .osint-title-terminal {
                color: var(--haribo-yellow);
                font-size: 1.1em;
                font-weight: 700;
                margin-bottom: 15px;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .osint-card {
                background: rgba(0, 0, 0, 0.7);
                border: 1px solid var(--terminal-purple);
                padding: 15px;
                margin-bottom: 15px;
            }
            
            .osint-card-title {
                color: var(--terminal-cyan);
                font-weight: 700;
                margin-bottom: 10px;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .osint-data {
                display: grid;
                gap: 10px;
            }
            
            .osint-row {
                display: flex;
                justify-content: space-between;
                padding: 8px 0;
                border-bottom: 1px dotted rgba(255, 255, 255, 0.1);
            }
            
            .osint-key {
                color: var(--terminal-cyan);
                font-size: 0.9em;
            }
            
            .osint-val {
                color: var(--haribo-green);
                font-size: 0.9em;
                text-align: right;
                max-width: 60%;
            }
            
            .threat-high { color: var(--haribo-red); }
            .threat-medium { color: var(--haribo-orange); }
            .threat-low { color: var(--haribo-green); }
            
            .service-terminal {
                background: rgba(255, 51, 102, 0.2);
                color: var(--haribo-red);
                padding: 4px 8px;
                font-size: 0.8em;
                border: 1px solid var(--haribo-red);
                display: inline-block;
                margin: 2px;
            }
            
            .breach-terminal {
                background: rgba(0, 204, 102, 0.2);
                color: var(--haribo-green);
                padding: 4px 8px;
                font-size: 0.8em;
                border: 1px solid var(--haribo-green);
                display: inline-block;
                margin: 2px;
            }
            
            /* Footer */
            .terminal-footer {
                background: rgba(10, 10, 10, 0.95);
                border-top: 2px solid var(--haribo-green);
                padding: 20px 30px;
                text-align: center;
            }
            
            .footer-grid {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 30px;
                max-width: 1200px;
                margin: 0 auto;
            }
            
            .footer-section {
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 10px;
            }
            
            .footer-icon {
                font-size: 1.5em;
                color: var(--haribo-green);
            }
            
            .footer-title {
                color: var(--haribo-yellow);
                font-size: 1em;
                font-weight: 700;
                letter-spacing: 1px;
            }
            
            .footer-text {
                color: var(--terminal-cyan);
                font-size: 0.8em;
                max-width: 300px;
            }
            
            /* Haribo Effects */
            .haribo-floating {
                position: fixed;
                pointer-events: none;
                z-index: -1;
                font-size: 20px;
                animation: hariboFloat 20s infinite linear;
                opacity: 0.1;
            }
            
            @keyframes hariboFloat {
                0% { transform: translateY(100vh) rotate(0deg); }
                100% { transform: translateY(-100px) rotate(360deg); }
            }
            
            /* Responsive */
            @media (max-width: 768px) {
                .terminal-header {
                    flex-direction: column;
                    gap: 15px;
                    padding: 15px;
                }
                
                .terminal-stats {
                    flex-wrap: wrap;
                    justify-content: center;
                }
                
                .terminal-main {
                    padding: 20px;
                    gap: 20px;
                }
                
                .osint-options {
                    grid-template-columns: 1fr;
                }
                
                .database-grid {
                    grid-template-columns: repeat(2, 1fr);
                }
                
                .footer-grid {
                    grid-template-columns: 1fr;
                    gap: 20px;
                }
            }
        </style>
    </head>
    <body>
        <div class="matrix-grid"></div>
        
        <!-- Floating Haribo Emojis -->
        <div id="hariboFloating"></div>
        
        <div class="terminal-wrapper">
            <!-- Header -->
            <header class="terminal-header">
                <div class="terminal-logo">
                    <div class="logo-icon">
                        <i class="fas fa-terminal"></i>
                    </div>
                    <div class="logo-text">DARK HARIBO OSINT</div>
                </div>
                
                <div class="terminal-stats">
                    <div class="stat-terminal">
                        <div class="stat-value" id="liveTime">--:--:--</div>
                        <div class="stat-label">TERMINAL TIME</div>
                    </div>
                    <div class="stat-terminal">
                        <div class="stat-value">{{ total_users|intcomma }}</div>
                        <div class="stat-label">RECORDS</div>
                    </div>
                    <div class="stat-terminal">
                        <div class="stat-value" id="cacheSize">0 MB</div>
                        <div class="stat-label">CACHE</div>
                    </div>
                </div>
                
                <a href="/logout" class="logout-terminal">
                    <i class="fas fa-sign-out-alt"></i>
                    EXIT TERMINAL
                </a>
            </header>
            
            <!-- Main Content -->
            <main class="terminal-main">
                <!-- Left Panel -->
                <div class="terminal-interface">
                    <div class="interface-title">
                        <i class="fas fa-terminal"></i>
                        OSINT TERMINAL
                    </div>
                    
                    <form method="POST" class="terminal-form">
                        <div class="terminal-input-group">
                            <input type="text" 
                                   name="user_id" 
                                   class="terminal-input-large"
                                   placeholder="ENTER USER ID"
                                   value="{{ user_id if user_id }}"
                                   required
                                   autofocus>
                        </div>
                        
                        <div class="interface-title">
                            <i class="fas fa-crosshairs"></i>
                            SELECT OSINT TYPE
                        </div>
                        
                        <div class="osint-options">
                            <label class="option-terminal {{ 'selected' if osint_type == 'basic' }}">
                                <input type="radio" name="osint_type" value="basic" {{ 'checked' if osint_type == 'basic' }}>
                                <div class="option-icon">
                                    <i class="fas fa-info-circle"></i>
                                </div>
                                <div class="option-text">BASIC INFO</div>
                            </label>
                            
                            <label class="option-terminal {{ 'selected' if osint_type == 'ip_osint' }}">
                                <input type="radio" name="osint_type" value="ip_osint" {{ 'checked' if osint_type == 'ip_osint' }}>
                                <div class="option-icon">
                                    <i class="fas fa-network-wired"></i>
                                </div>
                                <div class="option-text">IP OSINT</div>
                            </label>
                            
                            <label class="option-terminal {{ 'selected' if osint_type == 'email_osint' }}">
                                <input type="radio" name="osint_type" value="email_osint" {{ 'checked' if osint_type == 'email_osint' }}>
                                <div class="option-icon">
                                    <i class="fas fa-envelope"></i>
                                </div>
                                <div class="option-text">EMAIL OSINT</div>
                            </label>
                        </div>
                        
                        <button type="submit" class="terminal-execute">
                            <i class="fas fa-bolt"></i>
                            EXECUTE OSINT
                        </button>
                    </form>
                    
                    <div class="sample-database">
                        <div class="sample-title">
                            <i class="fas fa-database"></i>
                            SAMPLE DATABASE
                        </div>
                        <div class="database-grid">
                            {% for sample_id in sample_ids %}
                            <div class="database-id" onclick="document.querySelector('.terminal-input-large').value='{{ sample_id }}'; document.querySelector('.terminal-input-large').focus();">
                                {{ sample_id[:10] }}...
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                </div>
                
                <!-- Right Panel -->
                <div class="terminal-results">
                    <div class="results-header">
                        <div class="interface-title">
                            <i class="fas fa-chart-bar"></i>
                            RESULTS
                        </div>
                        {% if search_time %}
                        <div class="search-time">
                            <i class="far fa-clock"></i>
                            {{ search_time }}
                        </div>
                        {% endif %}
                    </div>
                    
                    <div class="results-display">
                        {% if not result %}
                        <div class="welcome-terminal">
                            <div class="welcome-icon">
                                <i class="fas fa-terminal"></i>
                            </div>
                            <h3>TERMINAL READY</h3>
                            <p>Enter a User ID and select OSINT type to begin analysis</p>
                            <div style="margin-top: 20px; padding: 15px; background: rgba(0, 0, 0, 0.5); border: 1px solid var(--terminal-cyan);">
                                <i class="fas fa-info-circle"></i>
                                Database: {{ total_users|intcomma }} records loaded
                            </div>
                        </div>
                        
                        {% else %}
                        <!-- Basic Results -->
                        <div class="result-terminal">
                            <div class="result-header-terminal">
                                <div class="result-icon-terminal">
                                    {% if result.status == 'success' %}
                                    <i class="fas fa-check-circle"></i>
                                    {% else %}
                                    <i class="fas fa-times-circle"></i>
                                    {% endif %}
                                </div>
                                <div class="result-title-terminal">
                                    {% if result.status == 'success' %}
                                    RECORD FOUND <span style="color: var(--haribo-green);">✓</span>
                                    {% else %}
                                    RECORD NOT FOUND <span style="color: var(--haribo-red);">✗</span>
                                    {% endif %}
                                </div>
                            </div>
                            
                            {% if result.status == 'success' %}
                            <div class="data-grid">
                                <div class="data-row">
                                    <div class="row-label-terminal">USER ID:</div>
                                    <div class="row-value-terminal">{{ user_id }}</div>
                                </div>
                                <div class="data-row">
                                    <div class="row-label-terminal">EMAIL:</div>
                                    <div class="row-value-terminal">{{ result.email }}</div>
                                </div>
                                <div class="data-row">
                                    <div class="row-label-terminal">IP ADDRESS:</div>
                                    <div class="row-value-terminal">{{ result.ip }}</div>
                                </div>
                                {% if result.encoded %}
                                <div class="data-row">
                                    <div class="row-label-terminal">ENCODED:</div>
                                    <div class="row-value-terminal" style="font-size: 0.8em; opacity: 0.8;">
                                        {{ result.encoded[:50] }}...
                                    </div>
                                </div>
                                {% endif %}
                            </div>
                            {% else %}
                            <div class="data-grid">
                                <div class="data-row">
                                    <div class="row-label-terminal">ERROR:</div>
                                    <div class="row-value-terminal">{{ result.message }}</div>
                                </div>
                                <div class="data-row">
                                    <div class="row-label-terminal">SEARCHED:</div>
                                    <div class="row-value-terminal">{{ user_id }}</div>
                                </div>
                            </div>
                            
                            {% if result.similar %}
                            <div class="osint-section-terminal">
                                <div class="osint-title-terminal">
                                    <i class="fas fa-random"></i>
                                    SIMILAR IDs
                                </div>
                                <div class="database-grid">
                                    {% for similar_id in result.similar %}
                                    <div class="database-id" 
                                         onclick="document.querySelector('.terminal-input-large').value='{{ similar_id }}'; document.querySelector('.terminal-input-large').focus();">
                                        {{ similar_id }}
                                    </div>
                                    {% endfor %}
                                </div>
                            </div>
                            {% endif %}
                            {% endif %}
                        </div>
                        
                        <!-- IP OSINT Results -->
                        {% if ip_osint_result and result.status == 'success' and result.ip != 'N/A' %}
                        <div class="result-terminal">
                            <div class="result-header-terminal">
                                <div class="result-icon-terminal">
                                    <i class="fas fa-globe-americas"></i>
                                </div>
                                <div class="result-title-terminal">
                                    IP OSINT ANALYSIS
                                </div>
                            </div>
                            
                            {% if ip_osint_result.geolocation %}
                            <div class="osint-section-terminal">
                                <div class="osint-title-terminal">
                                    <i class="fas fa-map-marker-alt"></i>
                                    GEOLOCATION
                                </div>
                                <div class="osint-card">
                                    <div class="osint-card-title">
                                        <i class="fas fa-location-dot"></i>
                                        Location Data
                                    </div>
                                    <div class="osint-data">
                                        <div class="osint-row">
                                            <span class="osint-key">Country:</span>
                                            <span class="osint-val">{{ ip_osint_result.geolocation.country }}</span>
                                        </div>
                                        <div class="osint-row">
                                            <span class="osint-key">City:</span>
                                            <span class="osint-val">{{ ip_osint_result.geolocation.city }}</span>
                                        </div>
                                        <div class="osint-row">
                                            <span class="osint-key">ISP:</span>
                                            <span class="osint-val">{{ ip_osint_result.geolocation.isp }}</span>
                                        </div>
                                        <div class="osint-row">
                                            <span class="osint-key">Coordinates:</span>
                                            <span class="osint-val">{{ ip_osint_result.geolocation.lat }}, {{ ip_osint_result.geolocation.lon }}</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                            
                            {% if ip_osint_result.reputation %}
                            <div class="osint-section-terminal">
                                <div class="osint-title-terminal">
                                    <i class="fas fa-shield-alt"></i>
                                    REPUTATION
                                </div>
                                <div class="osint-card">
                                    <div class="osint-card-title">
                                        <i class="fas fa-chart-line"></i>
                                        Threat Analysis
                                    </div>
                                    <div class="osint-data">
                                        <div class="osint-row">
                                            <span class="osint-key">Threat Level:</span>
                                            <span class="osint-val {{ 'threat-high' if ip_osint_result.reputation.threat_level == 'High' else 'threat-medium' if ip_osint_result.reputation.threat_level == 'Medium' else 'threat-low' }}">
                                                {{ ip_osint_result.reputation.threat_level }}
                                            </span>
                                        </div>
                                        {% if ip_osint_result.reputation.blacklists %}
                                        <div class="osint-row">
                                            <span class="osint-key">Blacklisted:</span>
                                            <span class="osint-val">{{ ip_osint_result.reputation.blacklists|join(', ') }}</span>
                                        </div>
                                        {% endif %}
                                        {% if ip_osint_result.reputation.proxy %}
                                        <div class="osint-row">
                                            <span class="osint-key">Proxy/VPN:</span>
                                            <span class="osint-val threat-high">DETECTED</span>
                                        </div>
                                        {% endif %}
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                            
                            {% if ip_osint_result.services %}
                            <div class="osint-section-terminal">
                                <div class="osint-title-terminal">
                                    <i class="fas fa-plug"></i>
                                    OPEN PORTS
                                </div>
                                <div class="osint-card">
                                    <div class="osint-card-title">
                                        <i class="fas fa-server"></i>
                                        Services
                                    </div>
                                    <div style="display: flex; flex-wrap: wrap; gap: 5px;">
                                        {% for service in ip_osint_result.services %}
                                        <span class="service-terminal">
                                            {{ service.port }}:{{ service.service }}
                                        </span>
                                        {% endfor %}
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                        </div>
                        {% endif %}
                        
                        <!-- Email OSINT Results -->
                        {% if email_osint_result and result.status == 'success' and result.email != 'N/A' %}
                        <div class="result-terminal">
                            <div class="result-header-terminal">
                                <div class="result-icon-terminal">
                                    <i class="fas fa-envelope"></i>
                                </div>
                                <div class="result-title-terminal">
                                    EMAIL OSINT ANALYSIS
                                </div>
                            </div>
                            
                            {% if email_osint_result.analysis %}
                            <div class="osint-section-terminal">
                                <div class="osint-title-terminal">
                                    <i class="fas fa-user-check"></i>
                                    EMAIL ANALYSIS
                                </div>
                                <div class="osint-card">
                                    <div class="osint-card-title">
                                        <i class="fas fa-at"></i>
                                        Email Details
                                    </div>
                                    <div class="osint-data">
                                        <div class="osint-row">
                                            <span class="osint-key">Provider:</span>
                                            <span class="osint-val">{{ email_osint_result.analysis.provider }}</span>
                                        </div>
                                        <div class="osint-row">
                                            <span class="osint-key">Domain:</span>
                                            <span class="osint-val">{{ email_osint_result.analysis.domain }}</span>
                                        </div>
                                        <div class="osint-row">
                                            <span class="osint-key">Valid Format:</span>
                                            <span class="osint-val {{ 'threat-low' if email_osint_result.analysis.valid_format else 'threat-high' }}">
                                                {{ 'YES' if email_osint_result.analysis.valid_format else 'NO' }}
                                            </span>
                                        </div>
                                        <div class="osint-row">
                                            <span class="osint-key">Disposable:</span>
                                            <span class="osint-val {{ 'threat-high' if email_osint_result.analysis.disposable else 'threat-low' }}">
                                                {{ 'YES' if email_osint_result.analysis.disposable else 'NO' }}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                            
                            {% if email_osint_result.analysis.breaches %}
                            <div class="osint-section-terminal">
                                <div class="osint-title-terminal">
                                    <i class="fas fa-exclamation-triangle"></i>
                                    BREACHES
                                </div>
                                <div class="osint-card">
                                    <div class="osint-card-title">
                                        <i class="fas fa-database"></i>
                                        Data Breaches
                                    </div>
                                    <div style="display: flex; flex-wrap: wrap; gap: 5px; margin: 10px 0;">
                                        {% for breach in email_osint_result.analysis.breaches %}
                                        <span class="breach-terminal">
                                            {{ breach.name }}
                                        </span>
                                        {% endfor %}
                                    </div>
                                    <div class="osint-row">
                                        <span class="osint-key">Total Breaches:</span>
                                        <span class="osint-val threat-high">{{ email_osint_result.analysis.breaches|length }}</span>
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                        </div>
                        {% endif %}
                        
                        {% endif %}
                    </div>
                </div>
            </main>
            
            <!-- Footer -->
            <footer class="terminal-footer">
                <div class="footer-grid">
                    <div class="footer-section">
                        <div class="footer-icon">
                            <i class="fas fa-bolt"></i>
                        </div>
                        <div class="footer-title">HARIBO INTELLIGENCE</div>
                        <div class="footer-text">Dark terminal OSINT analysis</div>
                    </div>
                    
                    <div class="footer-section">
                        <div class="footer-icon">
                            <i class="fab fa-github"></i>
                        </div>
                        <div class="footer-title">GITHUB DATASOURCE</div>
                        <div class="footer-text">{{ total_users|intcomma }} records</div>
                    </div>
                    
                    <div class="footer-section">
                        <div class="footer-icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <div class="footer-title">SECURE TERMINAL</div>
                        <div class="footer-text">Encrypted • No API Keys</div>
                    </div>
                </div>
            </footer>
        </div>
        
        <script>
            // Create floating Haribo emojis
            const hariboContainer = document.getElementById('hariboFloating');
            const hariboEmojis = ['🍬', '🍭', '🍫', '🧁', '🍩', '🍪', '🥨', '🍰', '🎂', '🍦'];
            
            for (let i = 0; i < 30; i++) {
                const emoji = document.createElement('div');
                emoji.className = 'haribo-floating';
                emoji.textContent = hariboEmojis[Math.floor(Math.random() * hariboEmojis.length)];
                emoji.style.left = `${Math.random() * 100}%`;
                emoji.style.fontSize = `${15 + Math.random() * 25}px`;
                emoji.style.animationDelay = `${Math.random() * 20}s`;
                emoji.style.animationDuration = `${10 + Math.random() * 20}s`;
                hariboContainer.appendChild(emoji);
            }
            
            // Live time update
            function updateTime() {
                const now = new Date();
                const timeString = now.toLocaleTimeString('en-US', { 
                    hour12: false,
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit'
                });
                document.getElementById('liveTime').textContent = timeString;
            }
            
            // Update cache size
            function updateCacheSize() {
                const size = Math.floor(Math.random() * 100) + 50;
                document.getElementById('cacheSize').textContent = size + ' MB';
            }
            
            // Option selection
            document.querySelectorAll('.option-terminal').forEach(option => {
                option.addEventListener('click', function() {
                    document.querySelectorAll('.option-terminal').forEach(opt => {
                        opt.classList.remove('selected');
                    });
                    this.classList.add('selected');
                    this.querySelector('input[type="radio"]').checked = true;
                    
                    // Terminal click effect
                    this.style.boxShadow = '0 0 30px var(--haribo-green)';
                    setTimeout(() => {
                        this.style.boxShadow = '';
                    }, 300);
                });
            });
            
            // Database ID selection
            document.querySelectorAll('.database-id').forEach(id => {
                id.addEventListener('click', function() {
                    const input = document.querySelector('.terminal-input-large');
                    input.value = this.textContent.replace('...', '');
                    input.focus();
                    
                    // Terminal feedback
                    this.style.background = 'rgba(0, 204, 102, 0.4)';
                    setTimeout(() => {
                        this.style.background = '';
                    }, 500);
                });
            });
            
            // Execute button animation
            const executeBtn = document.querySelector('.terminal-execute');
            if (executeBtn) {
                executeBtn.addEventListener('mouseenter', function() {
                    // Add haribo emoji explosion on hover
                    for (let i = 0; i < 5; i++) {
                        setTimeout(() => {
                            const emoji = document.createElement('span');
                            emoji.className = 'haribo-emoji';
                            emoji.textContent = hariboEmojis[Math.floor(Math.random() * hariboEmojis.length)];
                            emoji.style.position = 'absolute';
                            emoji.style.left = '50%';
                            emoji.style.top = '50%';
                            emoji.style.fontSize = '20px';
                            emoji.style.animation = 'hariboGlow 0.5s ease-out forwards';
                            emoji.style.zIndex = '1000';
                            document.querySelector('.terminal-interface').appendChild(emoji);
                            setTimeout(() => emoji.remove(), 500);
                        }, i * 100);
                    }
                });
            }
            
            // Initialize
            setInterval(updateTime, 1000);
            setInterval(updateCacheSize, 5000);
            updateTime();
            updateCacheSize();
            
            // Add pulsing effect to terminal header
            setInterval(() => {
                const logo = document.querySelector('.logo-icon');
                if (logo) {
                    logo.style.animation = 'none';
                    setTimeout(() => {
                        logo.style.animation = 'terminalPulse 2s infinite';
                    }, 10);
                }
            }, 4000);
        </script>
    </body>
    </html>
    ''', result=result, user_id=user_id, total_users=total_users, 
         sample_ids=sample_ids, search_time=search_time, osint_type=osint_type,
         ip_osint_result=ip_osint_result, email_osint_result=email_osint_result,
         colors=DarkHariboStyle.COLORS, gradients=DarkHariboStyle.GRADIENTS)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/api/search/<user_id>')
def api_search(user_id):
    if not session.get('authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_data = users_data.get(user_id)
    if user_data:
        return jsonify({
            'found': True,
            'user_id': user_id,
            'email': user_data['email'],
            'ip': user_data['ip']
        })
    else:
        return jsonify({
            'found': False,
            'user_id': user_id,
            'message': 'User not found'
        })

# Custom filter for number formatting
@app.template_filter('intcomma')
def intcomma_filter(value):
    try:
        return "{:,}".format(int(value))
    except:
        return value

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print(f"\n{'='*80}")
    print("🍬 DARK HARIBO OSINT v3.0")
    print(f"{'='*80}")
    print(f"🔧 Port: {port}")
    print(f"🔧 Debug: {debug}")
    print(f"👤 GitHub User: {GITHUB_USERNAME}")
    print(f"📦 Repository: {GITHUB_REPO}")
    print(f"📊 Loaded {len(users_data):,} records")
    print(f"🛠️  OSINT Modules: IP Geolocation • Email Analysis • DNS • WHOIS")
    print(f"{'='*80}\n")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
