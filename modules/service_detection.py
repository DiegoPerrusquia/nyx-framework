"""
NYX Framework - Service Detection Module (Optimized)
Advanced service and version detection using nmap-services database
"""

import socket
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import time
import json
import os
from pathlib import Path

from core.logger import get_logger

logger = get_logger(__name__)

@dataclass
class ServiceInfo:
    """Information about a detected service"""
    port: int
    protocol: str
    service: str
    version: Optional[str] = None
    product: Optional[str] = None
    cpe: Optional[str] = None
    banner: Optional[str] = None
    confidence: int = 0  # 0-100

class ServiceDetector:
    """Advanced service and version detection using nmap-services database"""
    
    def __init__(self, args):
        self.args = args
        self.timeout = args.timeout
        self.services_db = self._load_services_database()
        
    def _load_services_database(self) -> Dict[str, Any]:
        """Load services database from JSON file"""
        try:
            db_path = Path(__file__).parent.parent / 'data' / 'nmap_services.json'
            if db_path.exists():
                with open(db_path, 'r') as f:
                    db = json.load(f)
                    logger.debug(f"Loaded {len(db.get('services', {}))} services from database")
                    return db
            else:
                logger.warning(f"Services database not found at {db_path}, using minimal fallback")
                return self._get_fallback_database()
        except Exception as e:
            logger.error(f"Error loading services database: {e}")
            return self._get_fallback_database()
    
    def _get_fallback_database(self) -> Dict[str, Any]:
        """Fallback database if JSON file is not available"""
        return {
            "services": {
                "21": {"name": "ftp", "description": "FTP"},
                "22": {"name": "ssh", "description": "SSH"},
                "23": {"name": "telnet", "description": "Telnet"},
                "25": {"name": "smtp", "description": "SMTP"},
                "53": {"name": "dns", "description": "DNS"},
                "80": {"name": "http", "description": "HTTP"},
                "110": {"name": "pop3", "description": "POP3"},
                "135": {"name": "msrpc", "description": "Microsoft RPC"},
                "139": {"name": "netbios-ssn", "description": "NetBIOS"},
                "143": {"name": "imap", "description": "IMAP"},
                "443": {"name": "https", "description": "HTTPS"},
                "445": {"name": "microsoft-ds", "description": "SMB"},
                "3306": {"name": "mysql", "description": "MySQL"},
                "3389": {"name": "ms-wbt-server", "description": "RDP"},
                "5432": {"name": "postgresql", "description": "PostgreSQL"},
                "6379": {"name": "redis", "description": "Redis"},
                "8080": {"name": "http-proxy", "description": "HTTP Proxy"},
                "27017": {"name": "mongod", "description": "MongoDB"}
            },
            "signatures": {},
            "http_probes": []
        }
    
    def detect(self, target: str, open_ports: List[int]) -> Dict[str, Any]:
        """Detect services on open ports"""
        
        logger.info(f"Detecting services on {target} ({len(open_ports)} ports)")
        
        identified_services = []
        
        for port in open_ports:
            try:
                service_info = self._detect_service(target, port)
                if service_info:
                    identified_services.append(service_info.__dict__)
                    log_msg = f"  [{target}:{port}] {service_info.service}"
                    if service_info.product:
                        log_msg += f" - {service_info.product}"
                    if service_info.version:
                        log_msg += f" v{service_info.version}"
                    logger.info(log_msg)
                
            except Exception as e:
                logger.debug(f"Error detecting service on port {port}: {e}")
        
        return {
            'target': target,
            'identified': identified_services,
            'total_services': len(identified_services)
        }
    
    def _detect_service(self, target: str, port: int) -> Optional[ServiceInfo]:
        """Detect service on a specific port"""
        
        # Look up service from database
        port_str = str(port)
        service_data = self.services_db.get('services', {}).get(port_str, {})
        service_name = service_data.get('name', 'unknown')
        service_desc = service_data.get('description', '')
        
        # Create base service info
        service_info = ServiceInfo(
            port=port,
            protocol='tcp',
            service=service_name,
            confidence=50 if service_name != 'unknown' else 10
        )
        
        # Try to grab banner for version detection
        banner = self._grab_enhanced_banner(target, port, service_name)
        
        if banner:
            service_info.banner = banner[:200]
            
            # Try to match signatures from database
            signatures = self.services_db.get('signatures', {}).get(service_name, [])
            for sig in signatures:
                pattern = sig.get('pattern', '')
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    service_info.product = sig.get('product', 'Unknown')
                    service_info.confidence = 90
                    
                    # Extract version if specified
                    extract_idx = sig.get('extract_version', 0)
                    if extract_idx > 0 and len(match.groups()) >= extract_idx:
                        service_info.version = match.group(extract_idx)
                    
                    break
        
        # HTTP-specific enhanced detection
        if port in [80, 443, 8000, 8080, 8081, 8088, 8443, 8888] or 'http' in service_name:
            http_info = self._detect_http_enhanced(target, port)
            if http_info:
                return http_info
        
        # If still unknown and high confidence port, use database info
        if service_info.confidence >= 40:
            if not service_info.product and service_desc:
                service_info.product = service_desc
        
        return service_info
    
    def _grab_enhanced_banner(self, target: str, port: int, service: str) -> Optional[str]:
        """Grab banner with enhanced probing"""
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            # Service-specific probes
            probe = self._get_probe_for_service(service, target)
            
            if probe:
                sock.send(probe)
            
            # Receive banner
            banner = b''
            try:
                for _ in range(3):  # Try to read multiple times
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    banner += chunk
                    if len(banner) > 8192:
                        break
            except socket.timeout:
                pass
            
            sock.close()
            
            if banner:
                return banner.decode('utf-8', errors='ignore')
            
        except Exception as e:
            logger.debug(f"Banner grab failed for {target}:{port}: {e}")
        
        return None
    
    def _get_probe_for_service(self, service: str, target: str) -> Optional[bytes]:
        """Get appropriate probe for service"""
        
        # Stealth probes - look like legitimate traffic
        probes = {
            'http': f'GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: text/html,application/xhtml+xml\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: close\r\n\r\n'.encode(),
            'https': f'GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nConnection: close\r\n\r\n'.encode(),
            'http-proxy': f'GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n'.encode(),
            'http-alt': f'GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n'.encode(),
            'smtp': b'EHLO mailserver.local\r\n',
            'pop3': b'CAPA\r\n',
            'imap': b'A001 CAPABILITY\r\n',
            'ftp': b'',  # Wait for banner
            'redis': b'INFO SERVER\r\n',
            'mysql': b'',  # Wait for handshake
            'postgresql': b'',  # Wait for startup
            'ssh': b'',  # Wait for version string
            'telnet': b'',  # Wait for banner
            'ms-sql-s': b'\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00',  # TDS probe
            'microsoft-ds': b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00',  # SMB probe
            'netbios-ssn': b'\x81\x00\x00\x44',  # NetBIOS session request
            'msrpc': b'\x05\x00\x0b\x03\x10\x00\x00\x00',  # RPC bind
            'vnc': b'',  # Wait for RFB version
            'winrm': f'GET /wsman HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n'.encode(),
            'elasticsearch': f'GET / HTTP/1.1\r\nHost: {target}:9200\r\nConnection: close\r\n\r\n'.encode(),
            'mongodb': b'\x3a\x00\x00\x00',  # MongoDB handshake
        }
        
        return probes.get(service, b'')
    
    def _detect_http_enhanced(self, target: str, port: int) -> Optional[ServiceInfo]:
        """Enhanced HTTP/HTTPS service detection"""
        
        service_info = ServiceInfo(
            port=port,
            protocol='tcp',
            service='http' if port != 443 and port != 8443 else 'https',
            confidence=70
        )
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            # Send comprehensive HTTP request
            request = f'GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n'
            sock.send(request.encode())
            
            # Read response
            response = b''
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 16384:
                        break
            except:
                pass
            
            sock.close()
            response_str = response.decode('utf-8', errors='ignore')
            
            if 'HTTP/' not in response_str:
                return None
            
            service_info.confidence = 90
            service_info.banner = response_str[:200]
            
            # Check for proxy indicators
            proxy_indicators = ['Via:', 'X-Cache:', 'X-Proxy', 'X-Squid', 'X-Varnish']
            if any(indicator in response_str for indicator in proxy_indicators):
                service_info.service = 'http-proxy'
                service_info.product = 'HTTP Proxy'
            
            # Extract Server header
            server_match = re.search(r'Server:\s*([^\r\n]+)', response_str, re.IGNORECASE)
            if server_match:
                server_header = server_match.group(1).strip()
                service_info.product = server_header
                
                # Try to extract version using database signatures
                signatures = self.services_db.get('signatures', {}).get('http', [])
                for sig in signatures:
                    pattern = sig.get('pattern', '')
                    match = re.search(pattern, server_header, re.IGNORECASE)
                    if match:
                        service_info.product = sig.get('product', server_header)
                        extract_idx = sig.get('extract_version', 0)
                        if extract_idx > 0 and len(match.groups()) >= extract_idx:
                            service_info.version = match.group(extract_idx)
                        service_info.confidence = 95
                        break
            
            # Check for PHP
            php_match = re.search(r'X-Powered-By:\s*PHP/([\\d\\.]+)', response_str, re.IGNORECASE)
            if php_match and not service_info.version:
                if service_info.product:
                    service_info.product += f" (PHP {php_match.group(1)})"
                else:
                    service_info.product = f"PHP {php_match.group(1)}"
                    service_info.version = php_match.group(1)
            
            return service_info
            
        except Exception as e:
            logger.debug(f"HTTP detection failed for {target}:{port}: {e}")
        
        return None
