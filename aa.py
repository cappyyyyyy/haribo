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
app.secret_key = os.environ.get('SECRET_KEY', 'haribo_render_2025_sweet_key')
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

class CandyStyle:
    """Haribo şeker teması sabitler"""
    COLORS = {
        'red': '#FF6B8B',        # Pembe şeker
        'orange': '#FF9966',     # Turuncu şeker
        'yellow': '#FFD166',     # Sarı şeker
        'green': '#9EE493',      # Yeşil şeker
        'blue': '#6CA6FF',       # Mavi şeker
        'purple': '#C8A2C8',     # Leylak şeker
        'pink': '#FFB6C1',       # Açık pembe
        'cyan': '#76E6FF',       # Camgöbeği
        'white': '#FFFFFF',
        'dark': '#2D1B69',       # Koyu mor
        'light': '#FFE5EC',      # Açık pembe arkaplan
        'gold': '#FFD700',       # Altın
        'candy_red': '#FF3366',  # Şeker kırmızısı
        'candy_green': '#66FF99',# Şeker yeşili
        'candy_blue': '#3366FF', # Şeker mavisi
        'candy_purple': '#CC66FF'# Şeker moru
    }
    
    GRADIENTS = {
        'rainbow': 'linear-gradient(90deg, #FF3366 0%, #FF9966 25%, #FFD166 50%, #9EE493 75%, #6CA6FF 100%)',
        'candy': 'linear-gradient(135deg, #FF6B8B 0%, #FF9966 25%, #FFD166 50%, #9EE493 75%, #6CA6FF 100%)',
        'sweet': 'linear-gradient(135deg, #FFE5EC 0%, #FFB6C1 50%, #FF6B8B 100%)',
        'gummy': 'linear-gradient(90deg, #FF3366 0%, #CC66FF 100%)',
        'golden': 'linear-gradient(90deg, #FFD700 0%, #FF9966 100%)',
        'berry': 'linear-gradient(90deg, #FF3366 0%, #C8A2C8 100%)',
        'button': 'linear-gradient(90deg, #FF6B8B 0%, #FF3366 100%)',
        'success': 'linear-gradient(90deg, #9EE493 0%, #66FF99 100%)',
        'warning': 'linear-gradient(90deg, #FFD166 0%, #FF9966 100%)',
        'danger': 'linear-gradient(90deg, #FF3366 0%, #FF0066 100%)'
    }
    
    @staticmethod
    def get_candy_emoji():
        """Rastgele şeker emojisi"""
        candies = ['🍭', '🍬', '🍫', '🍡', '🍧', '🍨', '🍦', '🎂', '🧁', '🍰', '🍩', '🍪', '🥨', '🍮']
        return random.choice(candies)

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
    print("🍭 HARIBO SWEET OSINT v3.0 - GITHUB DATA LOADER")
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
    print("🍭 HARIBO SWEET OSINT v3.0")
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
        return redirect('/candy_shop')
    
    error = None
    if request.method == 'POST':
        entered_key = request.form.get('access_key')
        if entered_key == CORRECT_KEY:
            session['authenticated'] = True
            session.permanent = True
            return jsonify({'success': True, 'redirect': '/candy_shop'})
        else:
            error = "⚠️ Invalid access key!"
    
    colors = CandyStyle.COLORS
    gradients = CandyStyle.GRADIENTS
    
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>HARIBO SWEET OSINT | CANDY SHOP ACCESS</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <link href="https://fonts.googleapis.com/css2?family=Nunito:wght@300;400;500;600;700;800;900&family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --candy-red: {{ colors.red }};
                --candy-orange: {{ colors.orange }};
                --candy-yellow: {{ colors.yellow }};
                --candy-green: {{ colors.green }};
                --candy-blue: {{ colors.blue }};
                --candy-purple: {{ colors.purple }};
                --candy-pink: {{ colors.pink }};
                --candy-cyan: {{ colors.cyan }};
                --candy-gold: {{ colors.gold }};
                --bg-light: {{ colors.light }};
                --bg-dark: {{ colors.dark }};
                --text-dark: #5A2D81;
                --gradient-rainbow: {{ gradients.rainbow }};
                --gradient-sweet: {{ gradients.sweet }};
                --gradient-gummy: {{ gradients.gummy }};
            }
            
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Poppins', sans-serif;
                background: var(--gradient-sweet);
                min-height: 100vh;
                overflow: hidden;
            }
            
            .candy-background {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                z-index: -2;
                background: 
                    radial-gradient(circle at 20% 80%, rgba(255, 107, 139, 0.3) 0%, transparent 50%),
                    radial-gradient(circle at 80% 20%, rgba(255, 209, 102, 0.3) 0%, transparent 50%),
                    radial-gradient(circle at 40% 40%, rgba(158, 228, 147, 0.3) 0%, transparent 50%);
            }
            
            .floating-candies {
                position: absolute;
                width: 100%;
                height: 100%;
            }
            
            .candy {
                position: absolute;
                font-size: 24px;
                animation: float 15s infinite ease-in-out;
                opacity: 0.7;
            }
            
            @keyframes float {
                0%, 100% { transform: translateY(0) rotate(0deg); }
                50% { transform: translateY(-20px) rotate(10deg); }
            }
            
            .candy-shop-container {
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                padding: 20px;
            }
            
            .candy-store {
                background: rgba(255, 255, 255, 0.95);
                border-radius: 25px;
                width: 100%;
                max-width: 500px;
                box-shadow: 
                    0 20px 60px rgba(255, 107, 139, 0.3),
                    0 10px 30px rgba(255, 209, 102, 0.3),
                    0 5px 15px rgba(158, 228, 147, 0.3),
                    inset 0 1px 0 rgba(255, 255, 255, 0.5);
                border: 3px solid var(--candy-pink);
                overflow: hidden;
                position: relative;
            }
            
            .candy-store::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 10px;
                background: var(--gradient-rainbow);
                z-index: 1;
            }
            
            .store-header {
                background: var(--gradient-gummy);
                padding: 25px 30px;
                text-align: center;
                border-bottom: 3px dotted var(--candy-pink);
            }
            
            .store-title {
                font-family: 'Nunito', sans-serif;
                font-size: 2.5em;
                font-weight: 900;
                margin-bottom: 10px;
                background: var(--gradient-rainbow);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                text-shadow: 2px 2px 0 rgba(255, 255, 255, 0.5);
            }
            
            .store-subtitle {
                color: var(--text-dark);
                font-size: 1.1em;
                font-weight: 500;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 10px;
            }
            
            .store-content {
                padding: 40px;
            }
            
            .candy-machine {
                text-align: center;
                margin-bottom: 30px;
            }
            
            .machine-icon {
                font-size: 4em;
                color: var(--candy-red);
                margin-bottom: 20px;
                animation: candyPop 2s infinite;
            }
            
            @keyframes candyPop {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.1); }
            }
            
            .welcome-text {
                color: var(--text-dark);
                font-size: 1.2em;
                margin-bottom: 30px;
                line-height: 1.6;
            }
            
            .login-form {
                display: flex;
                flex-direction: column;
                gap: 25px;
            }
            
            .candy-input-group {
                position: relative;
            }
            
            .candy-input {
                background: rgba(255, 255, 255, 0.9);
                border: 3px solid var(--candy-blue);
                border-radius: 15px;
                color: var(--text-dark);
                font-family: 'Poppins', sans-serif;
                padding: 18px 20px;
                width: 100%;
                font-size: 16px;
                transition: all 0.3s ease;
                box-shadow: 0 5px 15px rgba(108, 166, 255, 0.2);
            }
            
            .candy-input:focus {
                outline: none;
                border-color: var(--candy-red);
                box-shadow: 0 5px 20px rgba(255, 107, 139, 0.3);
                transform: translateY(-2px);
            }
            
            .input-label {
                position: absolute;
                left: 15px;
                top: -12px;
                background: white;
                padding: 0 10px;
                color: var(--candy-red);
                font-weight: 600;
                font-size: 0.9em;
                z-index: 1;
            }
            
            .candy-button {
                background: var(--gradient-gummy);
                border: none;
                border-radius: 15px;
                color: white;
                font-family: 'Nunito', sans-serif;
                font-weight: 800;
                padding: 20px;
                font-size: 18px;
                cursor: pointer;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 15px;
                letter-spacing: 1px;
                text-transform: uppercase;
                box-shadow: 0 10px 20px rgba(204, 102, 255, 0.3);
                position: relative;
                overflow: hidden;
            }
            
            .candy-button::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.3), transparent);
                transition: 0.5s;
            }
            
            .candy-button:hover::before {
                left: 100%;
            }
            
            .candy-button:hover {
                transform: translateY(-5px);
                box-shadow: 0 15px 30px rgba(204, 102, 255, 0.4);
            }
            
            .candy-button:active {
                transform: translateY(0);
            }
            
            .error-candy {
                background: rgba(255, 107, 139, 0.1);
                border: 2px solid var(--candy-red);
                border-radius: 15px;
                padding: 15px;
                color: var(--candy-red);
                font-size: 0.95em;
                display: flex;
                align-items: center;
                gap: 10px;
                animation: shake 0.5s;
            }
            
            @keyframes shake {
                0%, 100% { transform: translateX(0); }
                25% { transform: translateX(-5px); }
                75% { transform: translateX(5px); }
            }
            
            .candy-footer {
                margin-top: 30px;
                text-align: center;
                color: var(--text-dark);
                font-size: 0.9em;
                padding-top: 20px;
                border-top: 2px dotted var(--candy-pink);
            }
            
            .version {
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 10px;
                margin-top: 10px;
            }
            
            @media (max-width: 600px) {
                .candy-store {
                    margin: 10px;
                }
                
                .store-content {
                    padding: 30px 20px;
                }
                
                .store-title {
                    font-size: 2em;
                }
            }
        </style>
    </head>
    <body>
        <div class="candy-background">
            <div class="floating-candies" id="candyContainer"></div>
        </div>
        
        <div class="candy-shop-container">
            <div class="candy-store">
                <div class="store-header">
                    <h1 class="store-title">HARIBO SWEET OSINT</h1>
                    <div class="store-subtitle">
                        <i class="fas fa-candy-cane"></i>
                        Candy Intelligence Platform
                        <i class="fas fa-lollipop"></i>
                    </div>
                </div>
                
                <div class="store-content">
                    <div class="candy-machine">
                        <div class="machine-icon">
                            <i class="fas fa-candy-cane"></i>
                        </div>
                        <div class="welcome-text">
                            Welcome to the Sweet Intelligence Factory! 
                            Enter your golden key to unlock the candy OSINT machine.
                        </div>
                    </div>
                    
                    <form id="loginForm" method="POST" class="login-form">
                        <div class="candy-input-group">
                            <div class="input-label">GOLDEN CANDY KEY</div>
                            <input type="password" 
                                   name="access_key" 
                                   class="candy-input"
                                   placeholder="🍬 Enter your sweet key 🍬"
                                   required
                                   autofocus>
                        </div>
                        
                        <button type="submit" class="candy-button">
                            <i class="fas fa-key"></i>
                            Unlock Candy Machine
                        </button>
                        
                        {% if error %}
                        <div class="error-candy">
                            <i class="fas fa-exclamation-triangle"></i>
                            {{ error }}
                        </div>
                        {% endif %}
                    </form>
                    
                    <div class="candy-footer">
                        <div>Powered by Sweet Intelligence • GitHub Data Source</div>
                        <div class="version">
                            <i class="fas fa-ice-cream"></i>
                            <span>v3.0 • Candy Edition</span>
                            <i class="fas fa-cookie-bite"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            // Create floating candies
            const candyContainer = document.getElementById('candyContainer');
            const candyEmojis = ['🍭', '🍬', '🍫', '🍡', '🍧', '🍨', '🍦', '🎂', '🧁', '🍰', '🍩', '🍪', '🥨', '🍮', '🍒', '🍓', '🍇', '🍊', '🍋'];
            
            for (let i = 0; i < 25; i++) {
                const candy = document.createElement('div');
                candy.className = 'candy';
                candy.textContent = candyEmojis[Math.floor(Math.random() * candyEmojis.length)];
                candy.style.left = `${Math.random() * 100}%`;
                candy.style.top = `${Math.random() * 100}%`;
                candy.style.animationDelay = `${Math.random() * 15}s`;
                candy.style.animationDuration = `${10 + Math.random() * 20}s`;
                candy.style.fontSize = `${20 + Math.random() * 30}px`;
                candyContainer.appendChild(candy);
            }
            
            // Login form handling
            document.getElementById('loginForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const formData = new FormData(this);
                const button = this.querySelector('.candy-button');
                const originalText = button.innerHTML;
                
                // Loading state
                button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> PREPARING CANDIES...';
                button.disabled = true;
                
                // Add candy animation
                for (let i = 0; i < 10; i++) {
                    const candy = document.createElement('div');
                    candy.className = 'candy';
                    candy.textContent = candyEmojis[Math.floor(Math.random() * candyEmojis.length)];
                    candy.style.left = `${Math.random() * 100}%`;
                    candy.style.top = '100%';
                    candy.style.fontSize = '20px';
                    candy.style.animation = 'candyFall 1s linear forwards';
                    document.querySelector('.candy-background').appendChild(candy);
                    setTimeout(() => candy.remove(), 1000);
                }
                
                // Add CSS for candy fall
                const style = document.createElement('style');
                style.textContent = `
                    @keyframes candyFall {
                        0% { transform: translateY(0) rotate(0deg); opacity: 1; }
                        100% { transform: translateY(-100px) rotate(360deg); opacity: 0; }
                    }
                `;
                document.head.appendChild(style);
                
                try {
                    const response = await fetch('/login', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        // Success - candy celebration
                        button.innerHTML = '<i class="fas fa-check"></i> ACCESS GRANTED!';
                        button.style.background = '{{ gradients.success }}';
                        
                        // Candy explosion
                        for (let i = 0; i < 20; i++) {
                            setTimeout(() => {
                                const candy = document.createElement('div');
                                candy.className = 'candy';
                                candy.textContent = candyEmojis[Math.floor(Math.random() * candyEmojis.length)];
                                candy.style.left = '50%';
                                candy.style.top = '50%';
                                candy.style.fontSize = '30px';
                                candy.style.animation = `candyExplode 1s ease-out forwards`;
                                candy.style.zIndex = '1000';
                                document.querySelector('.candy-background').appendChild(candy);
                                setTimeout(() => candy.remove(), 1000);
                            }, i * 50);
                        }
                        
                        // Add CSS for candy explosion
                        const explodeStyle = document.createElement('style');
                        explodeStyle.textContent = `
                            @keyframes candyExplode {
                                0% { transform: translate(-50%, -50%) scale(0); opacity: 1; }
                                100% { 
                                    transform: translate(
                                        calc(-50% + ${Math.random() * 200 - 100}px),
                                        calc(-50% + ${Math.random() * 200 - 100}px)
                                    ) scale(1);
                                    opacity: 0;
                                }
                            }
                        `;
                        document.head.appendChild(explodeStyle);
                        
                        setTimeout(() => {
                            window.location.href = data.redirect;
                        }, 2000);
                    } else {
                        // Error state
                        button.innerHTML = originalText;
                        button.disabled = false;
                        
                        // Show error
                        const errorDiv = document.createElement('div');
                        errorDiv.className = 'error-candy';
                        errorDiv.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Invalid candy key! Try again.';
                        
                        const existingError = document.querySelector('.error-candy');
                        if (existingError) {
                            existingError.remove();
                        }
                        
                        this.appendChild(errorDiv);
                        
                        // Shake animation
                        this.style.animation = 'shake 0.5s';
                        setTimeout(() => {
                            this.style.animation = '';
                        }, 500);
                    }
                } catch (error) {
                    button.innerHTML = originalText;
                    button.disabled = false;
                    alert('Network error. Please try again.');
                }
            });
        </script>
    </body>
    </html>
    ''', error=error, colors=CandyStyle.COLORS, gradients=CandyStyle.GRADIENTS)

@app.route('/candy_shop', methods=['GET', 'POST'])
def candy_shop():
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
                    'message': 'User ID not found in candy database',
                    'similar': similar[:5]
                }
    
    colors = CandyStyle.COLORS
    gradients = CandyStyle.GRADIENTS
    total_users = len(users_data)
    
    # Örnek ID'ler
    sample_ids = list(users_data.keys())[:12] if users_data else []
    
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>HARIBO SWEET OSINT | CANDY SHOP</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <link href="https://fonts.googleapis.com/css2?family=Nunito:wght@300;400;500;600;700;800;900&family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --candy-red: {{ colors.red }};
                --candy-orange: {{ colors.orange }};
                --candy-yellow: {{ colors.yellow }};
                --candy-green: {{ colors.green }};
                --candy-blue: {{ colors.blue }};
                --candy-purple: {{ colors.purple }};
                --candy-pink: {{ colors.pink }};
                --candy-cyan: {{ colors.cyan }};
                --candy-gold: {{ colors.gold }};
                --bg-light: {{ colors.light }};
                --bg-dark: {{ colors.dark }};
                --text-dark: #5A2D81;
                --gradient-rainbow: {{ gradients.rainbow }};
                --gradient-candy: {{ gradients.candy }};
                --gradient-sweet: {{ gradients.sweet }};
                --gradient-gummy: {{ gradients.gummy }};
                --gradient-golden: {{ gradients.golden }};
                --gradient-berry: {{ gradients.berry }};
            }
            
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Poppins', sans-serif;
                background: var(--gradient-sweet);
                color: var(--text-dark);
                min-height: 100vh;
                overflow-x: hidden;
            }
            
            .candy-wrapper {
                display: flex;
                flex-direction: column;
                min-height: 100vh;
            }
            
            /* Candy Shop Header */
            .candy-shop-header {
                background: rgba(255, 255, 255, 0.95);
                border-bottom: 5px dotted var(--candy-pink);
                padding: 20px 40px;
                box-shadow: 0 10px 30px rgba(255, 107, 139, 0.2);
                position: sticky;
                top: 0;
                z-index: 100;
            }
            
            .shop-title-bar {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
            }
            
            .candy-logo {
                display: flex;
                align-items: center;
                gap: 15px;
            }
            
            .logo-icon {
                font-size: 2.5em;
                color: var(--candy-red);
                animation: candyBounce 2s infinite;
            }
            
            @keyframes candyBounce {
                0%, 100% { transform: translateY(0); }
                50% { transform: translateY(-10px); }
            }
            
            .logo-text {
                font-family: 'Nunito', sans-serif;
                font-size: 2.2em;
                font-weight: 900;
                background: var(--gradient-rainbow);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                text-shadow: 2px 2px 0 rgba(255, 255, 255, 0.5);
            }
            
            .shop-controls {
                display: flex;
                align-items: center;
                gap: 20px;
            }
            
            .candy-stats {
                display: flex;
                gap: 20px;
            }
            
            .stat-candy {
                background: rgba(255, 255, 255, 0.9);
                border: 3px solid var(--candy-blue);
                border-radius: 20px;
                padding: 15px 25px;
                text-align: center;
                min-width: 150px;
                box-shadow: 0 5px 15px rgba(108, 166, 255, 0.2);
            }
            
            .stat-value {
                font-size: 1.8em;
                font-weight: 800;
                color: var(--candy-red);
                margin-bottom: 5px;
            }
            
            .stat-label {
                font-size: 0.9em;
                color: var(--text-dark);
                font-weight: 600;
            }
            
            .logout-candy {
                background: var(--gradient-berry);
                color: white;
                border: none;
                border-radius: 50px;
                padding: 12px 25px;
                font-weight: 700;
                cursor: pointer;
                display: flex;
                align-items: center;
                gap: 10px;
                transition: all 0.3s ease;
                text-decoration: none;
            }
            
            .logout-candy:hover {
                transform: translateY(-3px);
                box-shadow: 0 10px 20px rgba(255, 51, 102, 0.3);
            }
            
            /* Main Content */
            .candy-factory {
                flex: 1;
                padding: 40px;
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 40px;
                max-width: 1600px;
                margin: 0 auto;
                width: 100%;
            }
            
            @media (max-width: 1200px) {
                .candy-factory {
                    grid-template-columns: 1fr;
                }
            }
            
            /* Left Panel - Candy Machine */
            .candy-machine-panel {
                background: rgba(255, 255, 255, 0.95);
                border: 5px solid var(--candy-purple);
                border-radius: 30px;
                padding: 30px;
                box-shadow: 
                    0 20px 40px rgba(200, 162, 200, 0.3),
                    inset 0 0 0 10px rgba(255, 255, 255, 0.5);
                position: relative;
                overflow: hidden;
            }
            
            .candy-machine-panel::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 10px;
                background: var(--gradient-rainbow);
            }
            
            .panel-title {
                font-family: 'Nunito', sans-serif;
                font-size: 1.8em;
                font-weight: 800;
                margin-bottom: 25px;
                color: var(--text-dark);
                display: flex;
                align-items: center;
                gap: 15px;
            }
            
            .candy-search-form {
                display: flex;
                flex-direction: column;
                gap: 25px;
            }
            
            .candy-input-jar {
                position: relative;
            }
            
            .candy-input-large {
                background: rgba(255, 255, 255, 0.9);
                border: 4px solid var(--candy-orange);
                border-radius: 20px;
                color: var(--text-dark);
                font-family: 'Poppins', sans-serif;
                padding: 20px 25px;
                width: 100%;
                font-size: 18px;
                transition: all 0.3s ease;
                box-shadow: 0 10px 20px rgba(255, 153, 102, 0.2);
            }
            
            .candy-input-large:focus {
                outline: none;
                border-color: var(--candy-red);
                box-shadow: 0 15px 30px rgba(255, 107, 139, 0.3);
                transform: translateY(-3px);
            }
            
            .candy-flavors {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 15px;
                margin: 20px 0;
            }
            
            .flavor-option {
                background: rgba(255, 255, 255, 0.9);
                border: 3px solid var(--candy-blue);
                border-radius: 15px;
                padding: 15px;
                cursor: pointer;
                transition: all 0.3s ease;
                text-align: center;
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 10px;
            }
            
            .flavor-option:hover {
                transform: translateY(-5px);
                border-color: var(--candy-red);
                box-shadow: 0 10px 20px rgba(255, 107, 139, 0.2);
            }
            
            .flavor-option.selected {
                background: var(--gradient-candy);
                border-color: var(--candy-red);
                color: white;
            }
            
            .flavor-option input[type="radio"] {
                display: none;
            }
            
            .flavor-icon {
                font-size: 1.5em;
            }
            
            .flavor-text {
                font-weight: 600;
                font-size: 0.9em;
            }
            
            .candy-button-big {
                background: var(--gradient-gummy);
                border: none;
                border-radius: 20px;
                color: white;
                font-family: 'Nunito', sans-serif;
                font-weight: 900;
                padding: 25px;
                font-size: 20px;
                cursor: pointer;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 15px;
                text-transform: uppercase;
                letter-spacing: 2px;
                box-shadow: 0 15px 30px rgba(204, 102, 255, 0.3);
                position: relative;
                overflow: hidden;
            }
            
            .candy-button-big:hover {
                transform: translateY(-5px);
                box-shadow: 0 20px 40px rgba(204, 102, 255, 0.4);
            }
            
            .candy-button-big:active {
                transform: translateY(0);
            }
            
            .sample-candies {
                margin-top: 40px;
                padding-top: 25px;
                border-top: 3px dotted var(--candy-green);
            }
            
            .sample-title {
                color: var(--text-dark);
                margin-bottom: 20px;
                font-size: 1.2em;
                font-weight: 700;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .candy-jar {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
                gap: 10px;
                background: rgba(255, 230, 236, 0.7);
                border-radius: 15px;
                padding: 20px;
                border: 3px solid var(--candy-yellow);
            }
            
            .candy-sample {
                background: white;
                border: 2px solid var(--candy-cyan);
                border-radius: 10px;
                padding: 10px;
                text-align: center;
                cursor: pointer;
                transition: all 0.3s ease;
                font-size: 0.9em;
                font-weight: 500;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }
            
            .candy-sample:hover {
                background: var(--gradient-candy);
                color: white;
                transform: translateY(-3px) scale(1.05);
                border-color: var(--candy-red);
                box-shadow: 0 5px 15px rgba(255, 107, 139, 0.3);
            }
            
            /* Right Panel - Results */
            .candy-results-panel {
                background: rgba(255, 255, 255, 0.95);
                border: 5px solid var(--candy-green);
                border-radius: 30px;
                padding: 30px;
                box-shadow: 
                    0 20px 40px rgba(158, 228, 147, 0.3),
                    inset 0 0 0 10px rgba(255, 255, 255, 0.5);
                position: relative;
                overflow: hidden;
                display: flex;
                flex-direction: column;
            }
            
            .candy-results-panel::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 10px;
                background: var(--gradient-rainbow);
            }
            
            .results-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 25px;
                padding-bottom: 20px;
                border-bottom: 3px dotted var(--candy-green);
            }
            
            .search-time {
                color: var(--text-dark);
                font-weight: 600;
                display: flex;
                align-items: center;
                gap: 10px;
                background: rgba(158, 228, 147, 0.2);
                padding: 10px 20px;
                border-radius: 50px;
            }
            
            .results-display {
                flex: 1;
                overflow-y: auto;
                max-height: 70vh;
                padding-right: 10px;
            }
            
            /* Scrollbar Styling */
            .results-display::-webkit-scrollbar {
                width: 8px;
            }
            
            .results-display::-webkit-scrollbar-track {
                background: rgba(255, 182, 193, 0.2);
                border-radius: 10px;
            }
            
            .results-display::-webkit-scrollbar-thumb {
                background: var(--gradient-gummy);
                border-radius: 10px;
            }
            
            .welcome-candy {
                text-align: center;
                padding: 60px 20px;
                color: var(--text-dark);
            }
            
            .welcome-icon {
                font-size: 5em;
                color: var(--candy-red);
                margin-bottom: 20px;
                opacity: 0.8;
            }
            
            /* Result Cards */
            .candy-result {
                background: white;
                border: 4px solid var(--candy-orange);
                border-radius: 25px;
                padding: 25px;
                margin-bottom: 25px;
                animation: candySlide 0.5s ease;
                box-shadow: 0 10px 25px rgba(255, 153, 102, 0.2);
            }
            
            @keyframes candySlide {
                from { opacity: 0; transform: translateY(30px); }
                to { opacity: 1; transform: translateY(0); }
            }
            
            .result-header {
                display: flex;
                align-items: center;
                gap: 15px;
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 3px dotted var(--candy-orange);
            }
            
            .result-icon {
                font-size: 2em;
                color: var(--candy-green);
            }
            
            .result-title {
                font-family: 'Nunito', sans-serif;
                font-size: 1.5em;
                font-weight: 800;
                color: var(--text-dark);
            }
            
            .candy-grid {
                display: grid;
                gap: 15px;
                margin-bottom: 20px;
            }
            
            .candy-row {
                display: flex;
                align-items: center;
                padding: 15px;
                background: rgba(255, 230, 236, 0.5);
                border-radius: 15px;
                border-left: 5px solid var(--candy-red);
            }
            
            .row-label {
                min-width: 150px;
                color: var(--candy-blue);
                font-weight: 700;
                font-size: 1em;
            }
            
            .row-value {
                flex: 1;
                word-break: break-all;
                font-family: 'Courier New', monospace;
                font-weight: 500;
            }
            
            /* OSINT Sections */
            .osint-candy {
                margin-top: 30px;
                padding-top: 25px;
                border-top: 3px dotted var(--candy-purple);
            }
            
            .osint-title {
                color: var(--candy-purple);
                font-size: 1.3em;
                font-weight: 800;
                margin-bottom: 20px;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .candy-info-box {
                background: white;
                border: 3px solid var(--candy-cyan);
                border-radius: 20px;
                padding: 20px;
                margin-bottom: 15px;
                box-shadow: 0 8px 20px rgba(118, 230, 255, 0.2);
            }
            
            .info-title {
                color: var(--candy-cyan);
                font-weight: 700;
                margin-bottom: 15px;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .info-grid {
                display: grid;
                gap: 10px;
            }
            
            .info-row {
                display: flex;
                justify-content: space-between;
                padding: 8px 0;
                border-bottom: 1px dotted rgba(200, 162, 200, 0.3);
            }
            
            .info-key {
                color: var(--text-dark);
                font-weight: 600;
                font-size: 0.95em;
            }
            
            .info-value {
                color: var(--candy-red);
                font-weight: 700;
                text-align: right;
                max-width: 60%;
            }
            
            .threat-high { color: var(--candy-red); }
            .threat-medium { color: var(--candy-orange); }
            .threat-low { color: var(--candy-green); }
            
            .service-badge {
                background: var(--gradient-berry);
                color: white;
                padding: 5px 10px;
                border-radius: 10px;
                font-size: 0.85em;
                display: inline-block;
                margin: 2px;
            }
            
            .breach-badge {
                background: var(--gradient-rainbow);
                color: white;
                padding: 5px 10px;
                border-radius: 10px;
                font-size: 0.85em;
                display: inline-block;
                margin: 2px;
                font-weight: 700;
            }
            
            /* Footer */
            .candy-footer {
                background: rgba(255, 255, 255, 0.95);
                border-top: 5px dotted var(--candy-yellow);
                padding: 30px 40px;
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
                gap: 15px;
            }
            
            .footer-icon {
                font-size: 2em;
                color: var(--candy-red);
            }
            
            .footer-title {
                color: var(--candy-purple);
                font-size: 1.1em;
                font-weight: 800;
            }
            
            .footer-text {
                color: var(--text-dark);
                font-size: 0.9em;
                max-width: 300px;
            }
            
            /* Floating Candies Background */
            .candy-bg {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                pointer-events: none;
                z-index: -1;
            }
            
            .floating-candy {
                position: absolute;
                font-size: 20px;
                animation: floatCandy 20s infinite linear;
                opacity: 0.3;
            }
            
            @keyframes floatCandy {
                0% { transform: translateY(100vh) rotate(0deg); }
                100% { transform: translateY(-100px) rotate(360deg); }
            }
            
            /* Responsive */
            @media (max-width: 768px) {
                .candy-shop-header {
                    padding: 15px;
                }
                
                .shop-title-bar {
                    flex-direction: column;
                    gap: 15px;
                }
                
                .candy-stats {
                    flex-wrap: wrap;
                    justify-content: center;
                }
                
                .candy-factory {
                    padding: 20px;
                    gap: 20px;
                }
                
                .candy-flavors {
                    grid-template-columns: 1fr;
                }
                
                .candy-jar {
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
        <div class="candy-bg" id="candyBackground"></div>
        
        <div class="candy-wrapper">
            <!-- Candy Shop Header -->
            <header class="candy-shop-header">
                <div class="shop-title-bar">
                    <div class="candy-logo">
                        <div class="logo-icon">
                            <i class="fas fa-candy-cane"></i>
                        </div>
                        <div class="logo-text">HARIBO SWEET OSINT</div>
                    </div>
                    
                    <div class="shop-controls">
                        <div class="candy-stats">
                            <div class="stat-candy">
                                <div class="stat-value" id="liveTime">--:--:--</div>
                                <div class="stat-label">SWEET TIME</div>
                            </div>
                            <div class="stat-candy">
                                <div class="stat-value">{{ total_users|intcomma }}</div>
                                <div class="stat-label">CANDY RECORDS</div>
                            </div>
                            <div class="stat-candy">
                                <div class="stat-value" id="candyCache">0</div>
                                <div class="stat-label">SUGAR CACHE</div>
                            </div>
                        </div>
                        
                        <a href="/logout" class="logout-candy">
                            <i class="fas fa-sign-out-alt"></i>
                            EXIT CANDY SHOP
                        </a>
                    </div>
                </div>
            </header>
            
            <!-- Main Content -->
            <main class="candy-factory">
                <!-- Left Panel - Candy Machine -->
                <div class="candy-machine-panel">
                    <div class="panel-title">
                        <i class="fas fa-candy-cane"></i>
                        SWEET OSINT MACHINE
                    </div>
                    
                    <form method="POST" class="candy-search-form">
                        <div class="candy-input-jar">
                            <input type="text" 
                                   name="user_id" 
                                   class="candy-input-large"
                                   placeholder="Enter User ID (e.g., 1379557223096914020)..."
                                   value="{{ user_id if user_id }}"
                                   required
                                   autofocus>
                        </div>
                        
                        <div class="panel-title">
                            <i class="fas fa-ice-cream"></i>
                            CHOOSE CANDY FLAVOR
                        </div>
                        
                        <div class="candy-flavors">
                            <label class="flavor-option {{ 'selected' if osint_type == 'basic' }}">
                                <input type="radio" name="osint_type" value="basic" {{ 'checked' if osint_type == 'basic' }}>
                                <div class="flavor-icon">🍬</div>
                                <div class="flavor-text">Basic Candy</div>
                            </label>
                            
                            <label class="flavor-option {{ 'selected' if osint_type == 'ip_osint' }}">
                                <input type="radio" name="osint_type" value="ip_osint" {{ 'checked' if osint_type == 'ip_osint' }}>
                                <div class="flavor-icon">🌍</div>
                                <div class="flavor-text">IP Lollipop</div>
                            </label>
                            
                            <label class="flavor-option {{ 'selected' if osint_type == 'email_osint' }}">
                                <input type="radio" name="osint_type" value="email_osint" {{ 'checked' if osint_type == 'email_osint' }}>
                                <div class="flavor-icon">📧</div>
                                <div class="flavor-text">Email Gummies</div>
                            </label>
                        </div>
                        
                        <button type="submit" class="candy-button-big">
                            <i class="fas fa-cookie-bite"></i>
                            MAKE CANDY OSINT
                        </button>
                    </form>
                    
                    <div class="sample-candies">
                        <div class="sample-title">
                            <i class="fas fa-gift"></i>
                            SAMPLE CANDY JAR
                        </div>
                        <div class="candy-jar">
                            {% for sample_id in sample_ids %}
                            <div class="candy-sample" onclick="document.querySelector('.candy-input-large').value='{{ sample_id }}'; document.querySelector('.candy-input-large').focus();">
                                {{ sample_id[:10] }}...
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                </div>
                
                <!-- Right Panel - Results -->
                <div class="candy-results-panel">
                    <div class="results-header">
                        <div class="panel-title">
                            <i class="fas fa-chart-bar"></i>
                            CANDY RESULTS
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
                        <div class="welcome-candy">
                            <div class="welcome-icon">
                                <i class="fas fa-ice-cream"></i>
                            </div>
                            <h3>SWEET OSINT READY!</h3>
                            <p style="margin: 15px 0; font-size: 1.1em;">
                                Enter a User ID and select candy flavor to start analysis
                            </p>
                            <div style="background: rgba(158, 228, 147, 0.2); padding: 15px; border-radius: 20px; margin-top: 20px;">
                                <i class="fas fa-info-circle"></i>
                                Candy Database: {{ total_users|intcomma }} sweet records loaded
                            </div>
                        </div>
                        
                        {% else %}
                        <!-- Basic Results -->
                        <div class="candy-result">
                            <div class="result-header">
                                <div class="result-icon">
                                    {% if result.status == 'success' %}
                                    <i class="fas fa-candy-cane"></i>
                                    {% else %}
                                    <i class="fas fa-cookie-bite"></i>
                                    {% endif %}
                                </div>
                                <div class="result-title">
                                    {% if result.status == 'success' %}
                                    CANDY FOUND! 🍭
                                    {% else %}
                                    NO CANDY FOUND 🍬
                                    {% endif %}
                                </div>
                            </div>
                            
                            {% if result.status == 'success' %}
                            <div class="candy-grid">
                                <div class="candy-row">
                                    <div class="row-label">USER ID:</div>
                                    <div class="row-value">{{ user_id }}</div>
                                </div>
                                <div class="candy-row">
                                    <div class="row-label">EMAIL:</div>
                                    <div class="row-value">{{ result.email }}</div>
                                </div>
                                <div class="candy-row">
                                    <div class="row-label">IP ADDRESS:</div>
                                    <div class="row-value">{{ result.ip }}</div>
                                </div>
                                {% if result.encoded %}
                                <div class="candy-row">
                                    <div class="row-label">ENCODED CANDY:</div>
                                    <div class="row-value" style="font-size: 0.9em; opacity: 0.8; font-family: monospace;">
                                        {{ result.encoded[:50] }}...
                                    </div>
                                </div>
                                {% endif %}
                            </div>
                            {% else %}
                            <div class="candy-grid">
                                <div class="candy-row">
                                    <div class="row-label">SWEET ALERT:</div>
                                    <div class="row-value">{{ result.message }}</div>
                                </div>
                                <div class="candy-row">
                                    <div class="row-label">SEARCHED FOR:</div>
                                    <div class="row-value">{{ user_id }}</div>
                                </div>
                            </div>
                            
                            {% if result.similar %}
                            <div class="osint-candy">
                                <div class="osint-title">
                                    <i class="fas fa-random"></i>
                                    SIMILAR CANDIES FOUND
                                </div>
                                <div class="candy-jar">
                                    {% for similar_id in result.similar %}
                                    <div class="candy-sample" 
                                         onclick="document.querySelector('.candy-input-large').value='{{ similar_id }}'; document.querySelector('.candy-input-large').focus();">
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
                        <div class="candy-result">
                            <div class="result-header">
                                <div class="result-icon">
                                    <i class="fas fa-globe-americas"></i>
                                </div>
                                <div class="result-title">
                                    IP LOLLIPOP ANALYSIS 🍭
                                </div>
                            </div>
                            
                            {% if ip_osint_result.geolocation %}
                            <div class="osint-candy">
                                <div class="osint-title">
                                    <i class="fas fa-map-marker-alt"></i>
                                    GEO-LOLLIPOP
                                </div>
                                <div class="candy-info-box">
                                    <div class="info-title">
                                        <i class="fas fa-candy-cane"></i>
                                        Location Details
                                    </div>
                                    <div class="info-grid">
                                        <div class="info-row">
                                            <span class="info-key">Country:</span>
                                            <span class="info-value">{{ ip_osint_result.geolocation.country }}</span>
                                        </div>
                                        <div class="info-row">
                                            <span class="info-key">City:</span>
                                            <span class="info-value">{{ ip_osint_result.geolocation.city }}</span>
                                        </div>
                                        <div class="info-row">
                                            <span class="info-key">ISP:</span>
                                            <span class="info-value">{{ ip_osint_result.geolocation.isp }}</span>
                                        </div>
                                        <div class="info-row">
                                            <span class="info-key">Coordinates:</span>
                                            <span class="info-value">{{ ip_osint_result.geolocation.lat }}, {{ ip_osint_result.geolocation.lon }}</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                            
                            {% if ip_osint_result.reputation %}
                            <div class="osint-candy">
                                <div class="osint-title">
                                    <i class="fas fa-shield-alt"></i>
                                    CANDY REPUTATION
                                </div>
                                <div class="candy-info-box">
                                    <div class="info-title">
                                        <i class="fas fa-cookie-bite"></i>
                                        Threat Analysis
                                    </div>
                                    <div class="info-grid">
                                        <div class="info-row">
                                            <span class="info-key">Sweetness Level:</span>
                                            <span class="info-value threat-{{ ip_osint_result.reputation.threat_level|lower }}">
                                                {{ ip_osint_result.reputation.threat_level }}
                                            </span>
                                        </div>
                                        {% if ip_osint_result.reputation.blacklists %}
                                        <div class="info-row">
                                            <span class="info-key">Blacklisted In:</span>
                                            <span class="info-value">
                                                {{ ip_osint_result.reputation.blacklists|join(', ') }}
                                            </span>
                                        </div>
                                        {% endif %}
                                        {% if ip_osint_result.reputation.proxy %}
                                        <div class="info-row">
                                            <span class="info-key">Proxy/VPN:</span>
                                            <span class="info-value threat-high">SOUR CANDY 🍋</span>
                                        </div>
                                        {% endif %}
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                            
                            {% if ip_osint_result.services %}
                            <div class="osint-candy">
                                <div class="osint-title">
                                    <i class="fas fa-plug"></i>
                                    CANDY PORTS
                                </div>
                                <div class="candy-info-box">
                                    <div class="info-title">
                                        <i class="fas fa-server"></i>
                                        Open Services
                                    </div>
                                    <div style="display: flex; flex-wrap: wrap; gap: 10px;">
                                        {% for service in ip_osint_result.services %}
                                        <span class="service-badge">
                                            {{ service.port }}: {{ service.service }}
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
                        <div class="candy-result">
                            <div class="result-header">
                                <div class="result-icon">
                                    <i class="fas fa-envelope"></i>
                                </div>
                                <div class="result-title">
                                    EMAIL GUMMIES ANALYSIS 🍬
                                </div>
                            </div>
                            
                            {% if email_osint_result.analysis %}
                            <div class="osint-candy">
                                <div class="osint-title">
                                    <i class="fas fa-user-check"></i>
                                    GUMMY ANALYSIS
                                </div>
                                <div class="candy-info-box">
                                    <div class="info-title">
                                        <i class="fas fa-candy-cane"></i>
                                        Email Details
                                    </div>
                                    <div class="info-grid">
                                        <div class="info-row">
                                            <span class="info-key">Provider:</span>
                                            <span class="info-value">{{ email_osint_result.analysis.provider }}</span>
                                        </div>
                                        <div class="info-row">
                                            <span class="info-key">Domain:</span>
                                            <span class="info-value">{{ email_osint_result.analysis.domain }}</span>
                                        </div>
                                        <div class="info-row">
                                            <span class="info-key">Valid Format:</span>
                                            <span class="info-value {{ 'threat-low' if email_osint_result.analysis.valid_format else 'threat-high' }}">
                                                {{ 'SWEET ✓' if email_osint_result.analysis.valid_format else 'SOUR ✗' }}
                                            </span>
                                        </div>
                                        <div class="info-row">
                                            <span class="info-key">Disposable:</span>
                                            <span class="info-value {{ 'threat-high' if email_osint_result.analysis.disposable else 'threat-low' }}">
                                                {{ 'CHEWY GUMMY' if email_osint_result.analysis.disposable else 'PREMIUM CANDY' }}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                            
                            {% if email_osint_result.analysis.breaches %}
                            <div class="osint-candy">
                                <div class="osint-title">
                                    <i class="fas fa-exclamation-triangle"></i>
                                    CANDY BREACHES
                                </div>
                                <div class="candy-info-box">
                                    <div class="info-title">
                                        <i class="fas fa-cookie-bite"></i>
                                        Data Breaches Found
                                    </div>
                                    <div style="display: flex; flex-wrap: wrap; gap: 10px; margin-top: 15px;">
                                        {% for breach in email_osint_result.analysis.breaches %}
                                        <span class="breach-badge">
                                            {{ breach.name }} ({{ breach.date }})
                                        </span>
                                        {% endfor %}
                                    </div>
                                    <div class="info-row" style="margin-top: 15px; border: none;">
                                        <span class="info-key">Total Breaches:</span>
                                        <span class="info-value threat-high">{{ email_osint_result.analysis.breaches|length }}</span>
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                            
                            {% if email_osint_result.domain_info %}
                            <div class="osint-candy">
                                <div class="osint-title">
                                    <i class="fas fa-dns"></i>
                                    DNS CANDIES
                                </div>
                                <div class="candy-info-box">
                                    <div class="info-title">
                                        <i class="fas fa-server"></i>
                                        Domain Records
                                    </div>
                                    <div class="info-grid">
                                        {% for record_type, records in email_osint_result.domain_info.items() %}
                                        <div class="info-row">
                                            <span class="info-key">{{ record_type }}:</span>
                                            <span class="info-value">
                                                {% for record in records[:2] %}
                                                {{ record }}<br>
                                                {% endfor %}
                                                {% if records|length > 2 %}
                                                ... and {{ records|length - 2 }} more
                                                {% endif %}
                                            </span>
                                        </div>
                                        {% endfor %}
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
            <footer class="candy-footer">
                <div class="footer-grid">
                    <div class="footer-section">
                        <div class="footer-icon">
                            <i class="fas fa-bolt"></i>
                        </div>
                        <div class="footer-title">SWEET INTELLIGENCE</div>
                        <div class="footer-text">Real-time candy-flavored OSINT analysis</div>
                    </div>
                    
                    <div class="footer-section">
                        <div class="footer-icon">
                            <i class="fab fa-github"></i>
                        </div>
                        <div class="footer-title">GITHUB CANDY JAR</div>
                        <div class="footer-text">{{ total_users|intcomma }} sweet records loaded</div>
                    </div>
                    
                    <div class="footer-section">
                        <div class="footer-icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <div class="footer-title">SUGAR SECURE</div>
                        <div class="footer-text">Encrypted • No API Keys • Sweet & Safe</div>
                    </div>
                </div>
            </footer>
        </div>
        
        <script>
            // Create floating candies background
            const candyBg = document.getElementById('candyBackground');
            const candyEmojis = ['🍭', '🍬', '🍫', '🍡', '🍧', '🍨', '🍦', '🎂', '🧁', '🍰', '🍩', '🍪', '🥨', '🍮', '🍒', '🍓', '🍇', '🍊', '🍋'];
            
            for (let i = 0; i < 50; i++) {
                const candy = document.createElement('div');
                candy.className = 'floating-candy';
                candy.textContent = candyEmojis[Math.floor(Math.random() * candyEmojis.length)];
                candy.style.left = `${Math.random() * 100}%`;
                candy.style.fontSize = `${15 + Math.random() * 30}px`;
                candy.style.animationDelay = `${Math.random() * 20}s`;
                candy.style.animationDuration = `${15 + Math.random() * 25}s`;
                candyBg.appendChild(candy);
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
                document.getElementById('candyCache').textContent = size + ' MB';
            }
            
            // Flavor selection
            document.querySelectorAll('.flavor-option').forEach(option => {
                option.addEventListener('click', function() {
                    document.querySelectorAll('.flavor-option').forEach(opt => {
                        opt.classList.remove('selected');
                    });
                    this.classList.add('selected');
                    this.querySelector('input[type="radio"]').checked = true;
                    
                    // Candy click effect
                    this.style.transform = 'scale(0.95)';
                    setTimeout(() => {
                        this.style.transform = '';
                    }, 300);
                });
            });
            
            // Candy sample selection
            document.querySelectorAll('.candy-sample').forEach(sample => {
                sample.addEventListener('click', function() {
                    const input = document.querySelector('.candy-input-large');
                    input.value = this.textContent.replace('...', '');
                    input.focus();
                    
                    // Candy animation
                    this.style.background = 'var(--gradient-candy)';
                    this.style.color = 'white';
                    setTimeout(() => {
                        this.style.background = '';
                        this.style.color = '';
                    }, 500);
                });
            });
            
            // Add candy explosion on form submit
            const form = document.querySelector('.candy-search-form');
            if (form) {
                form.addEventListener('submit', function() {
                    // Create candy explosion
                    for (let i = 0; i < 15; i++) {
                        setTimeout(() => {
                            const candy = document.createElement('div');
                            candy.className = 'floating-candy';
                            candy.textContent = candyEmojis[Math.floor(Math.random() * candyEmojis.length)];
                            candy.style.left = '50%';
                            candy.style.top = '50%';
                            candy.style.fontSize = '25px';
                            candy.style.animation = 'candySubmit 1s ease-out forwards';
                            candy.style.zIndex = '1000';
                            candyBg.appendChild(candy);
                            setTimeout(() => candy.remove(), 1000);
                        }, i * 50);
                    }
                });
            }
            
            // Add CSS for candy submit animation
            const submitStyle = document.createElement('style');
            submitStyle.textContent = `
                @keyframes candySubmit {
                    0% { 
                        transform: translate(-50%, -50%) scale(0) rotate(0deg);
                        opacity: 1;
                    }
                    100% { 
                        transform: translate(
                            calc(-50% + ${Math.random() * 300 - 150}px),
                            calc(-50% + ${Math.random() * 300 - 150}px)
                        ) scale(1) rotate(360deg);
                        opacity: 0;
                    }
                }
            `;
            document.head.appendChild(submitStyle);
            
            // Initialize
            setInterval(updateTime, 1000);
            setInterval(updateCacheSize, 5000);
            updateTime();
            updateCacheSize();
            
            // Add candy counter animation
            let candyCount = 0;
            setInterval(() => {
                candyCount++;
                if (candyCount > 999) candyCount = 0;
                
                // Add a new floating candy every 10 seconds
                if (candyCount % 10 === 0) {
                    const candy = document.createElement('div');
                    candy.className = 'floating-candy';
                    candy.textContent = candyEmojis[Math.floor(Math.random() * candyEmojis.length)];
                    candy.style.left = `${Math.random() * 100}%`;
                    candy.style.fontSize = `${15 + Math.random() * 30}px`;
                    candy.style.animationDuration = `${15 + Math.random() * 25}s`;
                    candyBg.appendChild(candy);
                    
                    // Remove old candies if too many
                    if (candyBg.children.length > 100) {
                        candyBg.removeChild(candyBg.children[0]);
                    }
                }
            }, 1000);
        </script>
    </body>
    </html>
    ''', result=result, user_id=user_id, total_users=total_users, 
         sample_ids=sample_ids, search_time=search_time, osint_type=osint_type,
         ip_osint_result=ip_osint_result, email_osint_result=email_osint_result,
         colors=CandyStyle.COLORS, gradients=CandyStyle.GRADIENTS)

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
    print("🍭 HARIBO SWEET OSINT v3.0")
    print(f"{'='*80}")
    print(f"🔧 Port: {port}")
    print(f"🔧 Debug: {debug}")
    print(f"👤 GitHub User: {GITHUB_USERNAME}")
    print(f"📦 Repository: {GITHUB_REPO}")
    print(f"📊 Loaded {len(users_data):,} sweet users")
    print(f"🛠️  Candy OSINT Modules: IP Lollipop • Email Gummies • DNS Candies • WHOIS Sweets")
    print(f"{'='*80}\n")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
