#!/usr/bin/env python3
"""
NYX Scanner - Standalone Port & Service Discovery
Works with Python standard library only - no external dependencies
"""

import sys
import argparse
import time
import json
import threading
import socket
import secrets
import hashlib
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import webbrowser

# Add project directories to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.port_scanner import PortScanner
from modules.service_detection import ServiceDetector
from core.logger import setup_logger, get_logger
from utils.validator import validate_target
from utils.banner import display_banner

__version__ = "2.0.0"
__author__ = "NYX Security"

logger = get_logger(__name__)

# Global storage for web interface
web_scans = {}
web_results = {}

# Rate limiting - track requests per IP
rate_limit_store = {}
RATE_LIMIT_REQUESTS = 10  # Max requests
RATE_LIMIT_WINDOW = 60    # Per 60 seconds

# CSRF protection - store valid tokens per session
csrf_tokens = {}
CSRF_TOKEN_EXPIRY = 3600  # 1 hour

def print_banner():
    """Display banner from utils"""
    display_banner(__version__)

class WebHandler(BaseHTTPRequestHandler):
    """HTTP request handler for web interface"""
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass
    
    def check_rate_limit(self):
        """Check if client has exceeded rate limit"""
        client_ip = self.client_address[0]
        current_time = time.time()
        
        # Clean old entries
        if client_ip in rate_limit_store:
            rate_limit_store[client_ip] = [
                req_time for req_time in rate_limit_store[client_ip]
                if current_time - req_time < RATE_LIMIT_WINDOW
            ]
        else:
            rate_limit_store[client_ip] = []
        
        # Check limit
        if len(rate_limit_store[client_ip]) >= RATE_LIMIT_REQUESTS:
            return False
        
        # Add current request
        rate_limit_store[client_ip].append(current_time)
        return True
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        if path == '/' or path == '/index.html':
            # Redirect to scan page
            self.send_response(302)
            self.send_header('Location', '/scan')
            self.end_headers()
        elif path == '/scan':
            self.serve_scan_page()
        elif path.startswith('/api/'):
            self.handle_api_get(path)
        else:
            self.send_404()
    
    def do_POST(self):
        """Handle POST requests"""
        # Check rate limit for POST requests
        if not self.check_rate_limit():
            client_ip = self.client_address[0]
            logger.warning(f"Rate limit exceeded for {client_ip} on {self.path}")
            self.send_json_response({
                'error': 'Rate limit exceeded. Please wait before making more requests.'
            }, 429)
            return
        
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        if path.startswith('/api/'):
            self.handle_api_post(path)
        else:
            self.send_404()
    
    def serve_scan_page(self):
        """Serve scan interface"""
        html = self.get_scan_html()
        self.send_html_response(html)
    
    def handle_api_get(self, path):
        """Handle API GET requests"""
        # Cleanup old scans periodically
        if len(web_scans) > 5:  # Trigger cleanup when we have more than 5 scans
            self._cleanup_old_scans()
        
        # CSRF token endpoint
        if path == '/api/csrf-token':
            token = secrets.token_urlsafe(32)
            client_ip = self.client_address[0]
            csrf_tokens[token] = {
                'ip': client_ip,
                'timestamp': time.time()
            }
            self.send_json_response({'csrf_token': token})
            return
            
        if path == '/api/scans':
            scans = []
            for scan_id, scan_info in web_scans.items():
                scans.append({
                    'id': scan_id,
                    'target': scan_info['target'],
                    'status': scan_info['status'],
                    'start_time': scan_info['start_time']
                })
            self.send_json_response(scans)
        
        elif '/status' in path:
            scan_id = path.split('/')[-2]
            if scan_id in web_scans:
                scan_info = web_scans[scan_id].copy()
                if 'start_time' in scan_info:
                    elapsed = time.time() - scan_info['start_time']
                    scan_info['elapsed_time'] = elapsed
                self.send_json_response(scan_info)
            else:
                self.send_json_response({'error': 'Scan not found'}, 404)
        
        elif '/results' in path:
            scan_id = path.split('/')[-2]
            if scan_id in web_results:
                self.send_json_response(web_results[scan_id])
            else:
                self.send_json_response({'error': 'Results not found'}, 404)
        
        elif '/logs' in path:
            scan_id = path.split('/')[-2]
            if scan_id in web_scans and 'logs' in web_scans[scan_id]:
                self.send_json_response(web_scans[scan_id]['logs'])
            else:
                self.send_json_response([])
        
        else:
            self.send_json_response({'error': 'Invalid API endpoint'}, 404)
    
    def verify_csrf_token(self, token):
        """Verify CSRF token and cleanup expired ones"""
        # Cleanup expired tokens periodically
        current_time = time.time()
        expired_tokens = [t for t, data in csrf_tokens.items() 
                         if current_time - data['timestamp'] > CSRF_TOKEN_EXPIRY]
        for t in expired_tokens:
            del csrf_tokens[t]
        
        if not token or token not in csrf_tokens:
            return False
        
        token_data = csrf_tokens[token]
        
        # Check if token expired
        if current_time - token_data['timestamp'] > CSRF_TOKEN_EXPIRY:
            del csrf_tokens[token]
            return False
        
        # Check if IP matches (basic check)
        if token_data['ip'] != self.client_address[0]:
            return False
        
        return True
    
    def handle_api_post(self, path):
        """Handle API POST requests"""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data.decode('utf-8'))
            csrf_token = data.get('csrf_token')
            
            # Verify CSRF token for all POST requests
            if not self.verify_csrf_token(csrf_token):
                client_ip = self.client_address[0]
                logger.warning(f"CSRF token validation failed for {client_ip} on {path}")
                self.send_json_response({'error': 'Invalid or missing CSRF token. Please refresh the page.'}, 403)
                return
        except json.JSONDecodeError:
            self.send_json_response({'error': 'Invalid JSON'}, 400)
            return
        
        if path == '/api/scan':
            try:
                target = data.get('target', '')
                threads = data.get('threads', 50)
                timeout = data.get('timeout', 1)
                
                # Validate target to prevent command injection
                if not target or not validate_target(target):
                    client_ip = self.client_address[0]
                    logger.warning(f"Invalid target '{target}' from {client_ip} - possible injection attempt")
                    self.send_json_response({'error': 'Invalid target format. Use valid IP address or hostname.'}, 400)
                    return
                
                # Validate numeric parameters
                try:
                    threads = int(threads)
                    timeout = int(timeout)
                    if not (1 <= threads <= 200):
                        self.send_json_response({'error': 'Threads must be between 1 and 200'}, 400)
                        return
                    if not (1 <= timeout <= 10):
                        self.send_json_response({'error': 'Timeout must be between 1 and 10 seconds'}, 400)
                        return
                except (ValueError, TypeError):
                    self.send_json_response({'error': 'Invalid numeric parameters'}, 400)
                    return
                
                scan_id = self.start_background_scan(data)
                self.send_json_response({'scan_id': scan_id, 'status': 'started'})
            except Exception as e:
                self.send_json_response({'error': str(e)}, 400)
        
        elif path == '/api/pre-scan-check':
            try:
                target = data.get('target', '')
                
                # Validate target to prevent command injection
                if not target or not validate_target(target):
                    self.send_json_response({'error': 'Invalid target format. Use valid IP address or hostname.'}, 400)
                    return
                
                result = self.perform_pre_scan_check(target)
                self.send_json_response(result)
            except Exception as e:
                self.send_json_response({'error': str(e)}, 500)
        
        elif '/stop' in path:
            scan_id = path.split('/')[3]  # /api/scan/{scan_id}/stop
            if scan_id in web_scans:
                web_scans[scan_id]['status'] = 'stopped'
                web_scans[scan_id]['stop_requested'] = True
                self.send_json_response({'status': 'stopped'})
            else:
                self.send_json_response({'error': 'Scan not found'}, 404)
        
        else:
            self.send_json_response({'error': 'Invalid API endpoint'}, 404)
    
    def start_background_scan(self, data):
        """Start scan in background"""
        scan_id = f"scan_{int(time.time())}"
        
        # Parse custom ports if provided
        ports = data.get('ports', 'top-100')
        if ports not in ['top-20', 'top-100', 'top-1000', 'web', 'database', 'all']:
            # Custom port range or list
            try:
                # Validate custom ports format
                if ',' in ports or '-' in ports:
                    # Custom format like "80,443,8080" or "1-1000" or "22,80,443,1000-2000"
                    pass  # Port scanner will handle validation
            except:
                ports = 'top-100'  # Fallback
        
        # Store scan info
        web_scans[scan_id] = {
            'target': data.get('target', ''),
            'status': 'running',
            'start_time': time.time(),
            'ports_scanned': 0,
            'open_ports_found': 0,
            'progress': 0,
            'total_ports': 0,  # Will be set when scanner starts
            'verbose': data.get('verbose', False),
            'logs': [],  # Limit log size for memory efficiency
            'stop_requested': False,
            'max_logs': 100  # Limit to prevent memory overflow
        }
        
        # Start scan thread
        thread = threading.Thread(target=self.run_scan, args=(scan_id, data))
        thread.daemon = True
        thread.start()
        
        return scan_id
    
    def perform_pre_scan_check(self, target):
        """Check connectivity and OS detection with Linux distro fingerprinting"""
        import subprocess
        
        result = {
            'target': target,
            'reachable': False,
            'latency': None,
            'os_detected': None,
            'os_confidence': 0,
            'ttl': None,
            'error': None,
            'distro_hints': []
        }
        
        # Test 1: Ping test
        try:
            ping_result = subprocess.run(
                ['ping', '-c', '3', '-W', '2', target],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if ping_result.returncode == 0:
                result['reachable'] = True
                
                # Extract latency
                import re
                latency_match = re.search(r'time=(\d+\.?\d*)\s*ms', ping_result.stdout)
                if latency_match:
                    result['latency'] = float(latency_match.group(1))
                
                # Extract TTL for OS detection
                ttl_match = re.search(r'ttl=(\d+)', ping_result.stdout, re.IGNORECASE)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    result['ttl'] = ttl
                    
                    # Precise OS Detection based on TTL ranges (launchpad-style)
                    # TTL decreases by 1 per hop, so we detect the initial value
                    if 60 <= ttl <= 64:
                        result['os_detected'] = 'Linux/Unix'
                        result['os_confidence'] = 90
                    elif 56 <= ttl < 60:
                        result['os_detected'] = 'Linux (kernel 2.x-3.x)'
                        result['os_confidence'] = 85
                    elif 120 <= ttl <= 128:
                        result['os_detected'] = 'Windows 10/11/Server 2016+'
                        result['os_confidence'] = 92
                    elif 115 <= ttl < 120:
                        result['os_detected'] = 'Windows 7/8/Server 2008-2012'
                        result['os_confidence'] = 88
                    elif 240 <= ttl <= 255:
                        result['os_detected'] = 'Cisco IOS/Network Device'
                        result['os_confidence'] = 85
                    elif 200 <= ttl < 240:
                        result['os_detected'] = 'Solaris/AIX'
                        result['os_confidence'] = 80
                    elif ttl <= 55:
                        result['os_detected'] = 'Linux/Unix (distant)'
                        result['os_confidence'] = 70
                    elif ttl <= 115:
                        result['os_detected'] = 'Windows (distant)'
                        result['os_confidence'] = 70
                    else:
                        result['os_detected'] = 'Unknown'
                        result['os_confidence'] = 50
            else:
                result['error'] = 'Host unreachable (ping failed)'
                
        except subprocess.TimeoutExpired:
            result['error'] = 'Connection timeout'
        except Exception as e:
            result['error'] = f'Ping failed: {str(e)}'
        
        # Test 2: If ping failed, try TCP connection on common ports
        if not result['reachable']:
            common_ports = [80, 443, 22, 21, 3389]
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    start = time.time()
                    sock.connect((target, port))
                    latency = (time.time() - start) * 1000
                    sock.close()
                    
                    result['reachable'] = True
                    result['latency'] = round(latency, 2)
                    result['error'] = f'ICMP blocked, but port {port} is open'
                    break
                except:
                    continue
        
        # Test 3: If Linux detected, try to fingerprint distro (stealth)
        if result['reachable'] and 'Linux' in str(result.get('os_detected', '')):
            distro_info = self._fingerprint_linux_distro(target)
            if distro_info:
                result['os_detected'] = distro_info['distro']
                result['os_confidence'] = distro_info['confidence']
                result['distro_hints'] = distro_info.get('hints', [])
        
        return result
    
    def _fingerprint_linux_distro(self, target):
        """Stealth Linux distribution fingerprinting"""
        import socket
        import re
        
        hints = []
        distro = None
        confidence = 70
        
        # Method 1: SSH banner analysis (most reliable and stealth)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, 22))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if banner:
                hints.append(f"SSH: {banner.strip()}")
                
                # Ubuntu patterns
                if 'Ubuntu' in banner:
                    # Extract Ubuntu version from OpenSSH package version
                    if 'OpenSSH' in banner:
                        if '1ubuntu' in banner.lower():
                            match = re.search(r'(\d+)ubuntu', banner, re.IGNORECASE)
                            if match:
                                pkg_ver = match.group(1)
                                # Map package versions to Ubuntu releases
                                ubuntu_map = {
                                    '2': 'Ubuntu 20.04 LTS (Focal)',
                                    '3': 'Ubuntu 20.04/22.04',
                                    '4': 'Ubuntu 22.04 LTS (Jammy)',
                                    '5': 'Ubuntu 22.04/24.04',
                                    '6': 'Ubuntu 24.04 LTS (Noble)',
                                }
                                distro = ubuntu_map.get(pkg_ver, 'Ubuntu Linux')
                                confidence = 85
                    else:
                        distro = 'Ubuntu Linux'
                        confidence = 75
                
                # Debian patterns
                elif 'Debian' in banner or 'deb' in banner.lower():
                    if 'OpenSSH' in banner:
                        # Debian stable versions
                        if '9p1' in banner:
                            distro = 'Debian 11 (Bullseye) / 12 (Bookworm)'
                            confidence = 80
                        elif '8p1' in banner:
                            distro = 'Debian 10 (Buster)'
                            confidence = 80
                        else:
                            distro = 'Debian Linux'
                            confidence = 75
                    else:
                        distro = 'Debian Linux'
                        confidence = 70
                
                # Red Hat / CentOS / Rocky / Alma
                elif 'el8' in banner.lower() or 'el9' in banner.lower():
                    if 'el9' in banner.lower():
                        distro = 'RHEL 9 / Rocky 9 / AlmaLinux 9'
                        confidence = 80
                    elif 'el8' in banner.lower():
                        distro = 'RHEL 8 / CentOS 8 / Rocky 8'
                        confidence = 80
                    else:
                        distro = 'Red Hat Enterprise Linux'
                        confidence = 75
                
                # Fedora
                elif 'fc3' in banner.lower() or 'fc4' in banner.lower():
                    distro = 'Fedora Linux'
                    confidence = 75
                
                # Alpine Linux
                elif 'OpenSSH_9' in banner and len(banner) < 50:
                    # Alpine often has very minimal SSH banners
                    distro = 'Alpine Linux'
                    confidence = 70
                
                # Arch Linux
                elif 'Arch' in banner:
                    distro = 'Arch Linux'
                    confidence = 80
        
        except:
            pass
        
        # Method 2: HTTP Server fingerprinting (passive)
        if not distro:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((target, 80))
                request = f'GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n'
                sock.send(request.encode())
                
                response = b''
                try:
                    while len(response) < 4096:
                        chunk = sock.recv(1024)
                        if not chunk:
                            break
                        response += chunk
                except:
                    pass
                
                sock.close()
                response_str = response.decode('utf-8', errors='ignore')
                
                if response_str:
                    # Ubuntu/Debian Apache defaults
                    if 'Ubuntu' in response_str:
                        distro = 'Ubuntu Linux'
                        confidence = 75
                        hints.append("HTTP headers indicate Ubuntu")
                    elif 'Debian' in response_str:
                        distro = 'Debian Linux'
                        confidence = 75
                        hints.append("HTTP headers indicate Debian")
                    
                    # Check Apache version patterns
                    apache_match = re.search(r'Apache/(\d+\.\d+\.\d+)\s*\(([^)]+)\)', response_str)
                    if apache_match:
                        apache_os = apache_match.group(2)
                        hints.append(f"Apache: {apache_os}")
                        
                        if 'Ubuntu' in apache_os:
                            distro = 'Ubuntu Linux'
                            confidence = 80
                        elif 'Debian' in apache_os:
                            distro = 'Debian Linux'
                            confidence = 80
                        elif 'Red Hat' in apache_os or 'CentOS' in apache_os:
                            distro = 'Red Hat/CentOS'
                            confidence = 80
            
            except:
                pass
        
        # Method 3: Default service ports pattern analysis
        if not distro:
            # Ubuntu often has certain default service combinations
            # This is a fallback, very low confidence
            distro = 'Linux (Unknown distribution)'
            confidence = 60
        
        if distro:
            return {
                'distro': distro,
                'confidence': confidence,
                'hints': hints
            }
        
        return None
    
    def run_scan(self, scan_id, data):
        """Run scan in background thread"""
        def log_verbose(message, msg_type='info'):
            """Add verbose log message with memory limit"""
            if web_scans[scan_id]['verbose']:
                log_entry = {
                    'message': message,
                    'type': msg_type,
                    'timestamp': time.time()
                }
                logs = web_scans[scan_id]['logs']
                logs.append(log_entry)
                
                # Limit logs to prevent memory overflow
                max_logs = web_scans[scan_id].get('max_logs', 100)
                if len(logs) > max_logs:
                    web_scans[scan_id]['logs'] = logs[-max_logs:]  # Keep only last N logs
        
        try:
            # Create args object
            class ScanArgs:
                def __init__(self, data):
                    self.target = data.get('target', '')
                    self.ports = data.get('ports', 'top-100')
                    self.threads = data.get('threads', 100)
                    self.timeout = data.get('timeout', 3)
                    self.verbose = data.get('verbose', False)
                    self.silent = not self.verbose
                    self.mode = 'normal'
                    self.timing = 3
                    self.syn = False
                    self.connect = True
                    self.udp = False
                    self.null = False
                    self.fin = False
                    self.xmas = False
                    self.randomize_hosts = False
                    self.service_detection = data.get('services', False)
                    self.rate_limit = 0  # Add missing rate_limit attribute
            
            args = ScanArgs(data)
            
            # Log scan start
            log_verbose(f"Starting scan of {args.target} with {args.threads} threads", "info")
            log_verbose(f"Port range: {args.ports}", "info")
            
            # Initialize scanner
            scanner = PortScanner(args)
            
            # Set total ports for progress calculation
            web_scans[scan_id]['total_ports'] = len(scanner.ports)
            
            # Add progress callback for real-time updates
            def progress_callback(ports_scanned, open_ports_found, last_open_port=None):
                if scan_id in web_scans:
                    web_scans[scan_id]['ports_scanned'] = ports_scanned
                    web_scans[scan_id]['open_ports_found'] = open_ports_found
                    
                    # Calculate accurate progress
                    total_ports = web_scans[scan_id]['total_ports']
                    if total_ports > 0:
                        progress = (ports_scanned / total_ports) * 100
                        web_scans[scan_id]['progress'] = min(progress, 95)  # Cap at 95% until complete
                    
                    # Only log when a new open port is found
                    if last_open_port:
                        log_verbose(f"Open port found: {last_open_port}/tcp", "port")
            
            # Check for stop requests during scan
            def should_stop():
                return web_scans.get(scan_id, {}).get('stop_requested', False)
            
            # Perform scan
            results = scanner.scan(args.target, {
                'delay': 0,
                'randomize': False,
                'parallel': args.threads,
                'progress_callback': progress_callback,
                'should_stop': should_stop,
                'web_mode': True  # Suppress terminal output
            })
            
            # Clean results to remove non-serializable objects
            clean_results = self._clean_scan_results(results)
            
            # Check if scan was stopped
            if web_scans.get(scan_id, {}).get('stop_requested', False):
                web_scans[scan_id]['status'] = 'stopped'
                log_verbose("Scan stopped by user", "warning")
                return
            
            # Log results
            if results.get('open_ports'):
                log_verbose(f"Scan completed! Found {len(results['open_ports'])} open ports", "success")
                for port in results['open_ports']:
                    log_verbose(f"Port {port} is open", "port")
            else:
                log_verbose("Scan completed - no open ports found", "info")
            
            # Service detection if requested
            if data.get('services', False) and clean_results.get('open_ports'):
                web_scans[scan_id]['status'] = 'detecting_services'
                log_verbose("Starting service detection...", "info")
                
                service_detector = ServiceDetector(args)
                service_results = service_detector.detect(args.target, clean_results['open_ports'])
                clean_results['services'] = service_results
                
                if service_results.get('identified'):
                    log_verbose(f"Detected {len(service_results['identified'])} services", "success")
                    for svc in service_results['identified']:
                        version_info = f" v{svc['version']}" if svc.get('version') else ""
                        product_info = f" ({svc['product']})" if svc.get('product') else ""
                        log_verbose(f"Port {svc['port']}: {svc['service']}{version_info}{product_info}", "port")
                else:
                    log_verbose("No services identified", "info")
            
            # Store results
            web_results[scan_id] = clean_results
            web_scans[scan_id]['status'] = 'completed'
            web_scans[scan_id]['progress'] = 100
            
            # Clean up logs to save memory - keep only last 50 logs
            if len(web_scans[scan_id]['logs']) > 50:
                web_scans[scan_id]['logs'] = web_scans[scan_id]['logs'][-50:]
            
        except Exception as e:
            web_scans[scan_id]['status'] = 'error'
            web_scans[scan_id]['error'] = str(e)
            log_verbose(f"Scan error: {str(e)}", "error")
    
    def _clean_scan_results(self, results):
        """Clean scan results to remove non-JSON-serializable objects"""
        if not isinstance(results, dict):
            return results
        
        clean_results = {}
        for key, value in results.items():
            if callable(value):  # Skip functions
                continue
            elif isinstance(value, dict):
                clean_results[key] = self._clean_scan_results(value)
            elif isinstance(value, list):
                clean_results[key] = [self._clean_scan_results(item) if isinstance(item, dict) else item for item in value]
            else:
                clean_results[key] = value
        
        return clean_results
    
    def _cleanup_old_scans(self):
        """Clean up old scans to save memory"""
        current_time = time.time()
        max_age = 3600  # 1 hour
        
        # Clean old scan data
        scan_ids_to_remove = []
        for scan_id, scan_info in web_scans.items():
            scan_age = current_time - scan_info.get('start_time', current_time)
            if scan_age > max_age:
                scan_ids_to_remove.append(scan_id)
        
        # Remove old scans
        for scan_id in scan_ids_to_remove:
            if scan_id in web_scans:
                del web_scans[scan_id]
            if scan_id in web_results:
                del web_results[scan_id]
        
        # Limit total stored scans to 10
        if len(web_scans) > 10:
            oldest_scans = sorted(web_scans.items(), key=lambda x: x[1].get('start_time', 0))
            for scan_id, _ in oldest_scans[:-10]:  # Keep only last 10
                if scan_id in web_scans:
                    del web_scans[scan_id]
                if scan_id in web_results:
                    del web_results[scan_id]
    
    def send_html_response(self, html):
        """Send HTML response with security headers"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        # Security headers
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com")
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))
    
    def send_json_response(self, data, status=200):
        """Send JSON response with security headers"""
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.send_header('X-Content-Type-Options', 'nosniff')
        # Remove CORS for security (same-origin only)
        # self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))
    
    def send_404(self):
        """Send 404 response"""
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b'Not Found')
    
    def get_scan_html(self):
        """Get scan page HTML - load from compact template file"""
        try:
            template_path = Path(__file__).parent / 'web' / 'templates' / 'scan_compact.html'
            if template_path.exists():
                with open(template_path, 'r', encoding='utf-8') as f:
                    return f.read()
            else:
                # Fallback to old template if compact not found
                template_path = Path(__file__).parent / 'web' / 'templates' / 'scan.html'
                if template_path.exists():
                    with open(template_path, 'r', encoding='utf-8') as f:
                        return f.read()
                return self.get_embedded_scan_html()
        except Exception as e:
            logger.error(f"Error loading scan template: {e}")
            return self.get_embedded_scan_html()
    
    def get_embedded_scan_html(self):
        """Get embedded scan page HTML (fallback)"""
        return '''<!DOCTYPE html>
<html>
<head>
    <title>NYX Scanner - Network Scan</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 1rem; margin: -20px -20px 20px; }
        .nav { display: flex; gap: 1rem; }
        .nav a { color: white; text-decoration: none; padding: 0.5rem 1rem; border-radius: 4px; }
        .nav a:hover, .nav a.active { background: rgba(255,255,255,0.2); }
        .container { max-width: 1000px; margin: 0 auto; }
        .scan-section { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; }
        .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .form-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
        input, select { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; }
        .btn { width: 100%; padding: 0.75rem; background: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #2980b9; }
        .btn:disabled { background: #ccc; cursor: not-allowed; }
        .progress { margin-top: 1rem; }
        .progress-bar { width: 100%; height: 20px; background: #eee; border-radius: 10px; overflow: hidden; }
        .progress-fill { height: 100%; background: #3498db; width: 0%; transition: width 0.3s; }
        .results { margin-top: 2rem; display: none; }
        .action-card i {
            font-size: 3rem;
            margin-bottom: 1rem;
        }
        
        .action-card.scan { color: #3498db; }
        .action-card.history { color: #9b59b6; }
        .action-card.export { color: #27ae60; }
        
        .action-card h3 { margin: 0.5rem 0; color: #2c3e50; }
        .action-card p { color: #7f8c8d; font-size: 0.9rem; }
        
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 1rem; 
            margin: 2rem 0; 
        }
        
        .stat-card { 
            background: white; 
            padding: 1.5rem; 
            border-radius: 12px; 
            text-align: center; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            position: relative;
            overflow: hidden;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(90deg, #3498db, #2ecc71);
        }
        
        .stat-number { 
            font-size: 2.5rem; 
            font-weight: bold; 
            color: #3498db;
            margin: 0.5rem 0;
        }
        
        .stat-label {
            color: #7f8c8d;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .stat-icon {
            font-size: 2rem;
            color: #ecf0f1;
            margin-bottom: 0.5rem;
        }
        
        .recent-scans {
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin: 2rem 0;
        }
        
        .recent-scans h2 {
            color: #2c3e50;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .scan-list {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        
        .scan-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #3498db;
            transition: all 0.3s;
        }
        
        .scan-item:hover {
            background: #e9ecef;
            transform: translateX(5px);
        }
        
        .scan-info h4 {
            color: #2c3e50;
            margin-bottom: 0.3rem;
        }
        
        .scan-info p {
            color: #7f8c8d;
            font-size: 0.85rem;
        }
        
        .scan-status {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .status-badge {
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        
        .status-completed { background: #d4edda; color: #155724; }
        .status-running { background: #fff3cd; color: #856404; }
        .status-error { background: #f8d7da; color: #721c24; }
        
        .top-ports {
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin: 2rem 0;
        }
        
        .top-ports h2 {
            color: #2c3e50;
            margin-bottom: 1.5rem;
        }
        
        .port-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
            gap: 0.8rem;
        }
        
        .port-badge {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 0.8rem;
            border-radius: 8px;
            text-align: center;
            font-weight: 600;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .port-badge .port-number {
            font-size: 1.5rem;
            display: block;
        }
        
        .port-badge .port-service {
            font-size: 0.75rem;
            opacity: 0.9;
        }
        
        .empty-state {
            text-align: center;
            padding: 3rem;
            color: #7f8c8d;
        }
        
        .empty-state i {
            font-size: 4rem;
            margin-bottom: 1rem;
            opacity: 0.3;
        }
        
        .btn-primary {
            display: inline-block;
            padding: 1rem 2rem;
            background: linear-gradient(135deg, #3498db, #2ecc71);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s;
            box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3);
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(52, 152, 219, 0.4);
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="logo">
                <i class="fas fa-shield-alt"></i> NYX Scanner
            </div>
            <nav class="nav">
                <a href="/" class="active"><i class="fas fa-home"></i> Dashboard</a>
                <a href="/scan"><i class="fas fa-search"></i> Network Scan</a>
            </nav>
        </div>
    </div>
    
    <div class="container">
        <!-- Quick Actions -->
        <div class="quick-actions">
            <div class="action-card scan" onclick="window.location.href='/scan'">
                <i class="fas fa-radar"></i>
                <h3>New Scan</h3>
                <p>Start a new network scan</p>
            </div>
            <div class="action-card history" onclick="loadRecentScans()">
                <i class="fas fa-history"></i>
                <h3>Scan History</h3>
                <p>View past scan results</p>
            </div>
            <div class="action-card export" onclick="exportResults()">
                <i class="fas fa-download"></i>
                <h3>Export Data</h3>
                <p>Download scan reports</p>
            </div>
        </div>
        
        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card">
                <i class="fas fa-clipboard-list stat-icon"></i>
                <div class="stat-number" id="total-scans">0</div>
                <div class="stat-label">Total Scans</div>
            </div>
            <div class="stat-card">
                <i class="fas fa-circle-notch fa-spin stat-icon" id="active-icon" style="display:none;"></i>
                <i class="fas fa-play stat-icon" id="idle-icon"></i>
                <div class="stat-number" id="active-scans">0</div>
                <div class="stat-label">Active Scans</div>
            </div>
            <div class="stat-card">
                <i class="fas fa-network-wired stat-icon"></i>
                <div class="stat-number" id="total-hosts">0</div>
                <div class="stat-label">Hosts Scanned</div>
            </div>
            <div class="stat-card">
                <i class="fas fa-door-open stat-icon"></i>
                <div class="stat-number" id="total-ports">0</div>
                <div class="stat-label">Ports Found</div>
            </div>
        </div>
        
        <!-- Scan History Manager -->
        <div class="recent-scans">
            <h2>
                <i class="fas fa-history"></i> Scan History
                <button onclick="clearAllScans()" style="float: right; padding: 0.5rem 1rem; background: #e74c3c; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 0.85rem;">
                    <i class="fas fa-trash"></i> Clear All
                </button>
            </h2>
            <div class="scan-list" id="recent-scans-list">
                <div class="empty-state">
                    <i class="fas fa-inbox"></i>
                    <p>No scans yet. Start your first scan!</p>
                    <br>
                    <a href="/scan" class="btn-primary">
                        <i class="fas fa-plus"></i> Start Scan
                    </a>
                </div>
            </div>
        </div>
        
        <!-- Scan Details Modal -->
        <div id="scan-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 1000; overflow-y: auto;">
            <div style="background: white; max-width: 900px; margin: 2rem auto; border-radius: 12px; padding: 2rem; position: relative;">
                <button onclick="closeScanModal()" style="position: absolute; top: 1rem; right: 1rem; background: #e74c3c; color: white; border: none; border-radius: 50%; width: 35px; height: 35px; cursor: pointer; font-size: 1.2rem;">×</button>
                <div id="scan-modal-content"></div>
            </div>
        </div>
        
        <!-- Top Ports Found -->
        <div class="top-ports" id="top-ports-section" style="display:none;">
            <h2><i class="fas fa-chart-bar"></i> Most Common Ports Found</h2>
            <div class="port-list" id="top-ports-list"></div>
        </div>
    </div>
    
    <script>
        let allScans = [];
        
        async function loadStats() {
            try {
                const response = await fetch('/api/scans');
                allScans = await response.json();
                
                const totalScans = allScans.length;
                const activeScans = allScans.filter(s => s.status === 'running').length;
                
                document.getElementById('total-scans').textContent = totalScans;
                document.getElementById('active-scans').textContent = activeScans;
                
                // Show/hide active icon
                if (activeScans > 0) {
                    document.getElementById('active-icon').style.display = 'block';
                    document.getElementById('idle-icon').style.display = 'none';
                } else {
                    document.getElementById('active-icon').style.display = 'none';
                    document.getElementById('idle-icon').style.display = 'block';
                }
                
                // Load detailed stats
                await loadDetailedStats();
                await loadRecentScans();
                
            } catch (e) {
                console.error('Error loading stats:', e);
            }
        }
        
        async function loadDetailedStats() {
            let totalHosts = new Set();
            let totalPorts = 0;
            let portCounts = {};
            
            for (const scan of allScans) {
                try {
                    const response = await fetch(`/api/scan/${scan.id}/results`);
                    const result = await response.json();
                    
                    if (result.target) {
                        totalHosts.add(result.target);
                    }
                    
                    if (result.open_ports) {
                        totalPorts += result.open_ports.length;
                        result.open_ports.forEach(port => {
                            portCounts[port] = (portCounts[port] || 0) + 1;
                        });
                    }
                } catch (e) {}
            }
            
            document.getElementById('total-hosts').textContent = totalHosts.size;
            document.getElementById('total-ports').textContent = totalPorts;
            
            // Show top ports
            if (Object.keys(portCounts).length > 0) {
                showTopPorts(portCounts);
            }
        }
        
        function showTopPorts(portCounts) {
            const sortedPorts = Object.entries(portCounts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10);
            
            if (sortedPorts.length === 0) return;
            
            const portServices = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
                53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
                443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
                5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Proxy',
                27017: 'MongoDB'
            };
            
            const portList = document.getElementById('top-ports-list');
            portList.innerHTML = sortedPorts.map(([port, count]) => `
                <div class="port-badge">
                    <span class="port-number">${port}</span>
                    <span class="port-service">${portServices[port] || 'Unknown'}</span>
                </div>
            `).join('');
            
            document.getElementById('top-ports-section').style.display = 'block';
        }
        
        async function loadRecentScans() {
            const list = document.getElementById('recent-scans-list');
            
            if (allScans.length === 0) {
                list.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-inbox"></i>
                        <p>No scans yet. Start your first scan!</p>
                        <br>
                        <a href="/scan" class="btn-primary">
                            <i class="fas fa-plus"></i> Start Scan
                        </a>
                    </div>
                `;
                return;
            }
            
            // Load results for each scan
            const scansWithResults = await Promise.all(
                allScans.map(async scan => {
                    try {
                        const response = await fetch(`/api/scan/${scan.id}/results`);
                        if (response.ok) {
                            const results = await response.json();
                            return { ...scan, results };
                        }
                    } catch (e) {}
                    return { ...scan, results: null };
                })
            );
            
            list.innerHTML = scansWithResults.map(scan => {
                const statusClass = {
                    'completed': 'status-completed',
                    'running': 'status-running',
                    'error': 'status-error'
                }[scan.status] || 'status-completed';
                
                const statusText = scan.status.charAt(0).toUpperCase() + scan.status.slice(1);
                const date = new Date(scan.start_time * 1000).toLocaleString();
                
                const openPorts = scan.results?.open_ports?.length || 0;
                const services = scan.results?.services?.identified?.length || 0;
                
                return `
                    <div class="scan-item" style="cursor: pointer;" onclick="viewScanDetails('${scan.id}')">
                        <div class="scan-info">
                            <h4>${scan.target}</h4>
                            <p><i class="fas fa-clock"></i> ${date}</p>
                            ${openPorts > 0 ? `<p style="color: #3498db; font-size: 0.85rem;"><i class="fas fa-door-open"></i> ${openPorts} ports | <i class="fas fa-server"></i> ${services} services</p>` : ''}
                        </div>
                        <div class="scan-status" style="display: flex; gap: 8px; align-items: center;">
                            <span class="status-badge ${statusClass}">${statusText}</span>
                            <button onclick="event.stopPropagation(); rescanTarget('${scan.target}')" style="padding: 0.3rem 0.8rem; background: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.8rem;">
                                <i class="fas fa-redo"></i> Re-scan
                            </button>
                            <button onclick="event.stopPropagation(); deleteScan('${scan.id}')" style="padding: 0.3rem 0.8rem; background: #e74c3c; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.8rem;">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </div>
                `;
            }).join('');
        }
        
        async function viewScanDetails(scanId) {
            try {
                const response = await fetch(`/api/scan/${scanId}/results`);
                const results = await response.json();
                
                const modal = document.getElementById('scan-modal');
                const content = document.getElementById('scan-modal-content');
                
                const openPorts = results.open_ports || [];
                const services = results.services?.identified || [];
                
                content.innerHTML = `
                    <h2 style="color: #2c3e50; margin-bottom: 1rem;">Scan Results: ${results.target}</h2>
                    <p style="color: #666; margin-bottom: 2rem;">
                        Completed in ${results.scan_time?.toFixed(1)}s at ${results.scan_rate?.toFixed(0)} ports/sec
                    </p>
                    
                    <div style="margin-bottom: 2rem;">
                        <h3 style="color: #2c3e50; margin-bottom: 1rem;">Open Ports (${openPorts.length})</h3>
                        <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
                            ${openPorts.map(port => `<span style="background: #3498db; color: white; padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600;">${port}</span>`).join('')}
                        </div>
                        <button onclick="copyToClipboard('${openPorts.join(',')}')" style="margin-top: 1rem; padding: 0.5rem 1rem; background: #27ae60; color: white; border: none; border-radius: 6px; cursor: pointer;">
                            <i class="fas fa-copy"></i> Copy Ports
                        </button>
                    </div>
                    
                    ${services.length > 0 ? `
                        <div>
                            <h3 style="color: #2c3e50; margin-bottom: 1rem;">Services (${services.length})</h3>
                            <table style="width: 100%; border-collapse: collapse;">
                                <thead>
                                    <tr style="background: #f8f9fa;">
                                        <th style="padding: 0.8rem; text-align: left; border-bottom: 2px solid #dee2e6;">Port</th>
                                        <th style="padding: 0.8rem; text-align: left; border-bottom: 2px solid #dee2e6;">Service</th>
                                        <th style="padding: 0.8rem; text-align: left; border-bottom: 2px solid #dee2e6;">Version</th>
                                        <th style="padding: 0.8rem; text-align: left; border-bottom: 2px solid #dee2e6;">Product</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${services.map(svc => `
                                        <tr style="border-bottom: 1px solid #f1f3f4;">
                                            <td style="padding: 0.8rem;"><strong>${svc.port}</strong></td>
                                            <td style="padding: 0.8rem;">${svc.service || 'unknown'}</td>
                                            <td style="padding: 0.8rem;">${svc.version || '-'}</td>
                                            <td style="padding: 0.8rem;">${svc.product || '-'}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    ` : ''}
                `;
                
                modal.style.display = 'block';
            } catch (e) {
                alert('Failed to load scan details: ' + e.message);
            }
        }
        
        function closeScanModal() {
            document.getElementById('scan-modal').style.display = 'none';
        }
        
        function rescanTarget(target) {
            window.location.href = `/scan?target=${encodeURIComponent(target)}`;
        }
        
        async function deleteScan(scanId) {
            if (!confirm('Delete this scan?')) return;
            
            // Remove from local array
            allScans = allScans.filter(s => s.id !== scanId);
            await loadRecentScans();
            await loadStats();
        }
        
        async function clearAllScans() {
            if (!confirm('Delete all scan history? This cannot be undone.')) return;
            
            allScans = [];
            await loadRecentScans();
            await loadStats();
        }
        
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert('Copied to clipboard: ' + text);
            });
        }
        
        function exportResults() {
            if (allScans.length === 0) {
                alert('No scans to export');
                return;
            }
            alert('Export all scans functionality - Coming soon! You will be able to export all scan history to JSON or CSV.');
        }
        
        // Modal close event listeners
        window.onclick = function(event) {
            const modal = document.getElementById('scan-modal');
            if (event.target === modal) {
                closeScanModal();
            }
        };
        
        // Auto-refresh every 5 seconds
        setInterval(loadStats, 5000);
        loadStats();
    </script>
</body>
</html>'''

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='NYX Scanner - Standalone Port & Service Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python nyx.py scan 192.168.1.1                    # Quick scan
  python nyx.py scan example.com -p top-1000 -s     # Full scan with services
  python nyx.py web                                  # Start web interface
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Perform network scan')
    scan_parser.add_argument('target', help='Target IP or domain')
    scan_parser.add_argument('-p', '--ports', default='top-100',
                           help='Ports: top-20, top-100, top-1000, web, all, 1-1000, 22,80,443')
    scan_parser.add_argument('-s', '--services', action='store_true',
                           help='Enable service detection')
    scan_parser.add_argument('-t', '--threads', type=int, default=75,
                           help='Threads (default: 75, max: 100, stealth mode)')
    scan_parser.add_argument('--timeout', type=int, default=2,
                           help='Timeout in seconds (default: 2)')
    scan_parser.add_argument('-oG', '--output-grepable', type=str, metavar='FILE',
                           help='Save results in grepable format')
    scan_parser.add_argument('-oJ', '--output-json', type=str, metavar='FILE',
                           help='Save results in JSON format')
    scan_parser.add_argument('-oN', '--output-normal', type=str, metavar='FILE',
                           help='Save results in normal format')
    scan_parser.add_argument('--no-pre-scan', action='store_true',
                           help='Skip connectivity check and OS detection')
    scan_parser.add_argument('-v', '--verbose', action='count', default=0,
                           help='Increase verbosity')
    scan_parser.add_argument('--silent', action='store_true',
                           help='Silent mode (only show results)')
    
    # Web interface command
    web_parser = subparsers.add_parser('web', help='Start web interface')
    web_parser.add_argument('--host', default='127.0.0.1',
                          help='Host to bind (default: 127.0.0.1)')
    web_parser.add_argument('--port', type=int, default=8080,
                          help='Port to bind (default: 8080)')
    web_parser.add_argument('--no-browser', action='store_true',
                          help='Don\'t open browser automatically')
    
    return parser.parse_args()

def create_scanner_args(args):
    """Create args object for scanner compatibility"""
    class ScannerArgs:
        def __init__(self, args):
            self.target = args.target
            self.ports = args.ports
            self.threads = args.threads
            self.timeout = args.timeout
            self.verbose = args.verbose
            self.silent = args.silent
            self.mode = 'normal'
            self.timing = 3
            self.syn = False
            self.connect = True
            self.udp = False
            self.null = False
            self.fin = False
            self.xmas = False
            self.randomize_hosts = False
            self.service_detection = args.services
            self.rate_limit = None
            self.evasion = 'none'
            self.decoy = None
            self.spoof_source = None
            self.fragment = False
            self.badsum = False
    
    return ScannerArgs(args)

def parse_port_specification(port_spec):
    """Parse port specification: top-100, 1-1000, 22,80,443, etc."""
    import re
    
    # Predefined ranges
    presets = {
        'top-20': list(range(1, 21)),
        'top-100': list(range(1, 101)),
        'top-1000': list(range(1, 1001)),
        'web': [80, 443, 8000, 8080, 8443, 8888, 3000, 5000],
        'database': [1433, 1521, 3306, 5432, 27017, 6379, 9200],
        'all': list(range(1, 65536))
    }
    
    if port_spec in presets:
        return presets[port_spec]
    
    # Range format: 1-1000
    if '-' in port_spec and ',' not in port_spec:
        try:
            start, end = map(int, port_spec.split('-'))
            if 1 <= start <= end <= 65535:
                return list(range(start, end + 1))
        except:
            pass
    
    # Comma-separated: 22,80,443
    if ',' in port_spec:
        try:
            ports = [int(p.strip()) for p in port_spec.split(',')]
            if all(1 <= p <= 65535 for p in ports):
                return sorted(set(ports))
        except:
            pass
    
    # Mixed: 22,80-85,443
    if ',' in port_spec and '-' in port_spec:
        try:
            ports = []
            for part in port_spec.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                else:
                    ports.append(int(part))
            if all(1 <= p <= 65535 for p in ports):
                return sorted(set(ports))
        except:
            pass
    
    return None

def perform_cli_pre_scan(target, silent=False):
    """Perform pre-scan check with OS detection (like web interface)"""
    import subprocess
    import socket
    
    result = {
        'reachable': False,
        'latency': None,
        'os_detected': None,
        'os_confidence': None,
        'ttl': None,
        'distro_hints': []
    }
    
    try:
        # Try ping
        if not silent:
            print(f"[\033[96m◉\033[0m] Checking connectivity...", end='', flush=True)
        
        ping_cmd = ['ping', '-c', '1', '-W', '2', target]
        proc = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=3)
        
        if proc.returncode == 0:
            result['reachable'] = True
            
            # Extract TTL
            import re
            ttl_match = re.search(r'ttl=(\d+)', proc.stdout, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                result['ttl'] = ttl
                
                # OS detection based on TTL (like web)
                if 60 <= ttl <= 64:
                    result['os_detected'] = 'Linux/Unix'
                    result['os_confidence'] = 90
                elif 120 <= ttl <= 128:
                    result['os_detected'] = 'Windows 10/11/Server 2016+'
                    result['os_confidence'] = 92
                elif 115 <= ttl <= 119:
                    result['os_detected'] = 'Windows 7/8/Server 2008-2012'
                    result['os_confidence'] = 88
                elif 56 <= ttl <= 59:
                    result['os_detected'] = 'Linux (Kernel 2.x-3.x)'
                    result['os_confidence'] = 85
                elif 250 <= ttl <= 255:
                    result['os_detected'] = 'Cisco/Network Device'
                    result['os_confidence'] = 95
            
            # Extract latency
            time_match = re.search(r'time=([\d.]+)\s*ms', proc.stdout)
            if time_match:
                result['latency'] = float(time_match.group(1))
            
            # Try to get Linux distro hints (SSH banner)
            if result['os_detected'] and 'Linux' in result['os_detected']:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((target, 22))
                    banner = sock.recv(512).decode('utf-8', errors='ignore')
                    sock.close()
                    
                    if 'Ubuntu' in banner or 'ubuntu' in banner:
                        result['os_detected'] = 'Ubuntu Linux'
                        if '1ubuntu2' in banner:
                            result['distro_hints'].append('Ubuntu 20.04 LTS')
                        elif '1ubuntu4' in banner:
                            result['distro_hints'].append('Ubuntu 22.04 LTS')
                        elif '1ubuntu6' in banner:
                            result['distro_hints'].append('Ubuntu 24.04 LTS')
                    elif 'Debian' in banner:
                        result['os_detected'] = 'Debian Linux'
                except:
                    pass
            
            if not silent:
                print(f"\r[\033[92m✓\033[0m] Target is \033[92mreachable\033[0m")
                if result['latency']:
                    print(f"  ├─ Latency: \033[1m{result['latency']:.2f}ms\033[0m")
                if result['os_detected']:
                    print(f"  ├─ OS: \033[1m{result['os_detected']}\033[0m (Confidence: {result['os_confidence']}%)")
                if result['ttl']:
                    print(f"  ├─ TTL: \033[1m{result['ttl']}\033[0m")
                if result['distro_hints']:
                    print(f"  └─ Distro: \033[1m{', '.join(result['distro_hints'])}\033[0m")
        else:
            if not silent:
                print(f"\r[\033[93m⚠\033[0m] Ping failed, trying TCP...")
            # Try TCP connection to common port
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((target, 80))
                sock.close()
                result['reachable'] = True
                if not silent:
                    print(f"[\033[92m✓\033[0m] Target is \033[92mreachable\033[0m (via TCP)")
            except:
                pass
    
    except Exception as e:
        if not silent:
            print(f"\r[\033[91m✗\033[0m] Pre-scan check failed: {str(e)}")
    
    return result

def run_scan(args):
    """Execute network scan with pre-check and professional output"""
    if not args.silent:
        print_banner()
    
    setup_logger(args.verbose, silent=args.silent)
    
    # Validate target
    if not validate_target(args.target):
        print(f"\n[\033[91m✗\033[0m] Error: Invalid target '{args.target}'")
        return
    
    # Validate and limit threads (stealth mode)
    if args.threads > 100:
        print(f"\n[\033[93m⚠\033[0m] Limiting threads to 100 for stealth")
        args.threads = 100
    elif args.threads < 1:
        args.threads = 75
    
    # Validate timeout
    if args.timeout < 1 or args.timeout > 10:
        print(f"\n[\033[93m⚠\033[0m] Timeout must be 1-10 seconds, using default: 2")
        args.timeout = 2
    
    start_time = time.time()
    
    # Pre-scan check (connectivity + OS detection)
    pre_scan_result = None
    if not args.no_pre_scan:
        if not args.silent:
            print(f"\n[\033[96m◉\033[0m] Running pre-scan check on \033[1m{args.target}\033[0m...")
        pre_scan_result = perform_cli_pre_scan(args.target, args.silent)
        if not pre_scan_result.get('reachable'):
            print(f"\n[\033[91m✗\033[0m] Target unreachable. Scan aborted.")
            return
    
    # Parse ports
    ports_to_scan = parse_port_specification(args.ports)
    if not ports_to_scan:
        print(f"\n[\033[91m✗\033[0m] Invalid port specification: {args.ports}")
        return
    
    # Create scanner
    scanner_args = create_scanner_args(args)
    scanner = PortScanner(scanner_args)
    
    # Perform scan with progress
    if not args.silent:
        print(f"\n[\033[96m◉\033[0m] Scanning \033[1m{len(ports_to_scan)}\033[0m ports with \033[1m{args.threads}\033[0m threads (stealth mode)...")
    
    results = scanner.scan(args.target, {
        'delay': 0.01,  # Small delay for stealth
        'randomize': True,  # Randomize port order
        'parallel': args.threads
    })
    
    if 'error' in results:
        print(f"\n[\033[91m✗\033[0m] Scan failed: {results['error']}")
        return
    
    # Service detection
    if args.services and results.get('open_ports'):
        if not args.silent:
            print(f"[\033[96m◉\033[0m] Detecting services on \033[1m{len(results['open_ports'])}\033[0m open ports...")
        service_detector = ServiceDetector(scanner_args)
        service_results = service_detector.detect(args.target, results['open_ports'])
        results['services'] = service_results
    
    # Add pre-scan info to results
    if pre_scan_result:
        results['pre_scan'] = pre_scan_result
    
    # Display results
    display_scan_results(results, args, pre_scan_result)
    
    # Save outputs
    save_scan_outputs(results, args)
    
    scan_time = time.time() - start_time
    if not args.silent:
        print(f"\n[\033[92m✓\033[0m] Scan completed in \033[1m{scan_time:.2f}s\033[0m")

def display_scan_results(results, args, pre_scan_result=None):
    """Display scan results with professional formatting"""
    print("\n" + "="*70)
    print(" " * 20 + "\033[96m◉ NYX SCANNER RESULTS ◉\033[0m")
    print("="*70)
    
    # Target info
    print(f"\n[\033[96m▸\033[0m] \033[1mTarget:\033[0m {results.get('target')} ({results.get('ip')})")
    
    # Pre-scan info
    if pre_scan_result:
        if pre_scan_result.get('os_detected'):
            print(f"[\033[96m▸\033[0m] \033[1mOS:\033[0m {pre_scan_result['os_detected']} ({pre_scan_result.get('os_confidence', 0)}%)")
        if pre_scan_result.get('distro_hints'):
            print(f"[\033[96m▸\033[0m] \033[1mDistro:\033[0m {', '.join(pre_scan_result['distro_hints'])}")
    
    # Scan stats
    print(f"[\033[96m▸\033[0m] \033[1mScan Time:\033[0m {results.get('scan_time', 0):.2f}s")
    print(f"[\033[96m▸\033[0m] \033[1mScan Rate:\033[0m {results.get('scan_rate', 0):.0f} ports/sec")
    print(f"[\033[96m▸\033[0m] \033[1mPorts Scanned:\033[0m {results.get('ports_scanned', 0)}")
    
    # Open ports
    open_ports = results.get('open_ports', [])
    print(f"\n[\033[92m✓\033[0m] \033[1;92mOpen Ports ({len(open_ports)}):\033[0m")
    if open_ports:
        ports_str = ', '.join(map(str, open_ports))
        print(f"    {ports_str}")
    else:
        print("    \033[93mNo open ports found\033[0m")
    
    # Services
    if 'services' in results:
        services = results['services'].get('identified', [])
        if services:
            print(f"\n[\033[96m◉\033[0m] \033[1mServices Detected ({len(services)}):\033[0m")
            print("    " + "-"*62)
            print(f"    {'Port':<8} {'Service':<20} {'Version':<30}")
            print("    " + "-"*62)
            for svc in services:
                port = str(svc.get('port', '?'))
                service = (svc.get('service') or 'unknown')[:19]
                version = (svc.get('version') or '-')[:29]
                product = svc.get('product', '')
                if product and version == '-':
                    version = product[:29]
                print(f"    \033[92m{port:<8}\033[0m {service:<20} {version:<30}")
    
    print("\n" + "="*70)

def save_scan_outputs(results, args):
    """Save scan outputs in various formats"""
    from datetime import datetime
    
    # Grepeable format (compatible with zshrc functions)
    if hasattr(args, 'output_grepable') and args.output_grepable:
        try:
            with open(args.output_grepable, 'w') as f:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                target = results.get('target', 'unknown')
                ip = results.get('ip', target)
                
                # Header
                f.write(f"# Nyx scan report for {target} ({ip})\n")
                f.write(f"# Scan started at {timestamp}\n")
                
                # Ports line (compatible with extractports())
                open_ports = results.get('open_ports', [])
                if open_ports:
                    ports_str = ','.join(map(str, open_ports))
                    f.write(f"Host: {ip}\tPorts: {ports_str}\n")
                
                # Services (compatible with extractver())
                if 'services' in results:
                    services = results['services'].get('identified', [])
                    for svc in services:
                        port = svc.get('port', '?')
                        service = svc.get('service') or 'unknown'
                        version = svc.get('version') or ''
                        product = svc.get('product') or ''
                        state = 'open'
                        
                        # Format: Host: IP Ports: PORT/STATE/SERVICE/VERSION/PRODUCT
                        version_info = f"{version} {product}".strip() or '-'
                        f.write(f"Host: {ip}\tPorts: {port}/{state}/{service}//{version_info}/\n")
                
                # Footer
                f.write(f"# Scan finished at {timestamp}\n")
                f.write(f"# {len(open_ports)} ports found\n")
            
            print(f"[\033[92m✓\033[0m] Grepeable output saved: \033[1m{args.output_grepable}\033[0m")
        except Exception as e:
            print(f"[\033[91m✗\033[0m] Failed to save grepeable output: {e}")
    
    # JSON format
    if hasattr(args, 'output_json') and args.output_json:
        try:
            with open(args.output_json, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"[\033[92m✓\033[0m] JSON output saved: \033[1m{args.output_json}\033[0m")
        except Exception as e:
            print(f"[\033[91m✗\033[0m] Failed to save JSON output: {e}")
    
    # Normal format
    if hasattr(args, 'output_normal') and args.output_normal:
        try:
            with open(args.output_normal, 'w') as f:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                f.write(f"NYX Scanner Report\n")
                f.write(f"="*60 + "\n\n")
                f.write(f"Target: {results.get('target')} ({results.get('ip')})\n")
                f.write(f"Scan Time: {results.get('scan_time', 0):.2f}s\n")
                f.write(f"Scan Date: {timestamp}\n\n")
                
                open_ports = results.get('open_ports', [])
                f.write(f"Open Ports ({len(open_ports)}):\n")
                if open_ports:
                    f.write(f"  {', '.join(map(str, open_ports))}\n\n")
                
                if 'services' in results:
                    services = results['services'].get('identified', [])
                    if services:
                        f.write(f"Services ({len(services)}):\n")
                        f.write("-"*60 + "\n")
                        f.write(f"{'Port':<8} {'Service':<20} {'Version'}\n")
                        f.write("-"*60 + "\n")
                        for svc in services:
                            port = str(svc.get('port', '?'))
                            service = (svc.get('service') or 'unknown')[:19]
                            version = (svc.get('version') or '-')
                            f.write(f"{port:<8} {service:<20} {version}\n")
            
            print(f"[\033[92m✓\033[0m] Normal output saved: \033[1m{args.output_normal}\033[0m")
        except Exception as e:
            print(f"[\033[91m✗\033[0m] Failed to save normal output: {e}")

def start_web_interface(args):
    """Start standalone web interface"""
    try:
        print_banner()
        print(f"Starting web interface on http://{args.host}:{args.port}")
        print("Press Ctrl+C to stop")
        
        # Start server
        server = HTTPServer((args.host, args.port), WebHandler)
        
        # Open browser
        if not args.no_browser:
            try:
                webbrowser.open(f'http://{args.host}:{args.port}')
            except:
                pass
        
        server.serve_forever()
        
    except KeyboardInterrupt:
        print("\nShutting down web interface...")
    except Exception as e:
        print(f"Error starting web interface: {e}")

def main():
    """Main entry point"""
    args = parse_arguments()
    
    if not args.command:
        print_banner()
        print("Usage:")
        print("  python nyx.py scan <target>     # Perform network scan")
        print("  python nyx.py web               # Start web interface")
        print("\nFor detailed help: python nyx.py <command> --help")
        return
    
    try:
        if args.command == 'scan':
            run_scan(args)
        elif args.command == 'web':
            start_web_interface(args)
    
    except KeyboardInterrupt:
        print("\nOperation cancelled")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()