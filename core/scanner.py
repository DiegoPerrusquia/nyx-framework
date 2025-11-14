"""
NYX Framework - Advanced Scanner Core
Low-level packet manipulation and scanning techniques
"""

import socket
import struct
import random
import time
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from core.logger import get_logger

logger = get_logger(__name__)

class ScanType(Enum):
    """Enumeration of scan types"""
    TCP_SYN = "syn"
    TCP_CONNECT = "connect"
    TCP_NULL = "null"
    TCP_FIN = "fin"
    TCP_XMAS = "xmas"
    TCP_ACK = "ack"
    TCP_WINDOW = "window"
    UDP = "udp"
    SCTP_INIT = "sctp"

@dataclass
class ScanResult:
    """Result of a port scan"""
    port: int
    state: str  # open, closed, filtered, open|filtered
    service: Optional[str] = None
    banner: Optional[str] = None
    ttl: Optional[int] = None
    response_time: Optional[float] = None

class AdvancedScanner:
    """Advanced network scanner with multiple techniques"""
    
    def __init__(self, args):
        self.args = args
        self.timeout = args.timeout
        self.rate_limit = args.rate_limit
        
    def tcp_syn_scan(self, target: str, port: int) -> ScanResult:
        """
        TCP SYN scan (stealth scan)
        Requires raw socket privileges
        """
        try:
            # This is a simplified version - full implementation requires raw sockets
            start_time = time.time()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # In real implementation, we'd craft SYN packet manually
            result = sock.connect_ex((target, port))
            response_time = time.time() - start_time
            
            sock.close()
            
            if result == 0:
                return ScanResult(
                    port=port,
                    state="open",
                    response_time=response_time
                )
            else:
                return ScanResult(
                    port=port,
                    state="closed",
                    response_time=response_time
                )
                
        except socket.timeout:
            return ScanResult(port=port, state="filtered")
        except Exception as e:
            logger.debug(f"Error scanning port {port}: {e}")
            return ScanResult(port=port, state="error")
    
    def tcp_connect_scan(self, target: str, port: int) -> ScanResult:
        """
        TCP Connect scan (full 3-way handshake)
        Most reliable but easily detected
        """
        try:
            start_time = time.time()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((target, port))
            response_time = time.time() - start_time
            
            if result == 0:
                # Try to grab banner
                banner = self._grab_banner(sock)
                sock.close()
                
                return ScanResult(
                    port=port,
                    state="open",
                    banner=banner,
                    response_time=response_time
                )
            else:
                sock.close()
                return ScanResult(
                    port=port,
                    state="closed",
                    response_time=response_time
                )
                
        except socket.timeout:
            return ScanResult(port=port, state="filtered")
        except Exception as e:
            logger.debug(f"Error in connect scan port {port}: {e}")
            return ScanResult(port=port, state="error")
    
    def tcp_null_scan(self, target: str, port: int) -> ScanResult:
        """
        TCP NULL scan - no flags set
        Can evade some firewalls
        """
        # Placeholder - requires raw sockets
        logger.debug(f"NULL scan on {target}:{port}")
        return ScanResult(port=port, state="unknown")
    
    def tcp_fin_scan(self, target: str, port: int) -> ScanResult:
        """
        TCP FIN scan - only FIN flag set
        Stealthy scan technique
        """
        # Placeholder - requires raw sockets
        logger.debug(f"FIN scan on {target}:{port}")
        return ScanResult(port=port, state="unknown")
    
    def tcp_xmas_scan(self, target: str, port: int) -> ScanResult:
        """
        TCP XMAS scan - FIN, PSH, URG flags set
        Like a Christmas tree
        """
        # Placeholder - requires raw sockets
        logger.debug(f"XMAS scan on {target}:{port}")
        return ScanResult(port=port, state="unknown")
    
    def udp_scan(self, target: str, port: int) -> ScanResult:
        """
        UDP scan - challenging due to lack of responses
        """
        try:
            start_time = time.time()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty UDP packet
            sock.sendto(b'', (target, port))
            
            try:
                # Wait for response
                data, addr = sock.recvfrom(1024)
                response_time = time.time() - start_time
                sock.close()
                
                return ScanResult(
                    port=port,
                    state="open",
                    response_time=response_time
                )
            except socket.timeout:
                # No response could mean open or filtered
                sock.close()
                return ScanResult(port=port, state="open|filtered")
                
        except Exception as e:
            logger.debug(f"Error in UDP scan port {port}: {e}")
            return ScanResult(port=port, state="error")
    
    def _grab_banner(self, sock: socket.socket, timeout: float = 2.0) -> Optional[str]:
        """Attempt to grab service banner"""
        try:
            sock.settimeout(timeout)
            
            # Try receiving data (some services send banner immediately)
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    return banner
            except socket.timeout:
                pass
            
            # Try sending common probes
            probes = [
                b'\r\n',
                b'HEAD / HTTP/1.0\r\n\r\n',
                b'\x00\x00\x00\x00',
            ]
            
            for probe in probes:
                try:
                    sock.send(probe)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        return banner
                except:
                    continue
            
            return None
            
        except Exception as e:
            logger.debug(f"Banner grab failed: {e}")
            return None
    
    def scan_port(self, target: str, port: int, scan_type: ScanType) -> ScanResult:
        """Execute scan based on scan type"""
        
        # Rate limiting
        if self.rate_limit:
            time.sleep(1.0 / self.rate_limit)
        
        scan_methods = {
            ScanType.TCP_SYN: self.tcp_syn_scan,
            ScanType.TCP_CONNECT: self.tcp_connect_scan,
            ScanType.TCP_NULL: self.tcp_null_scan,
            ScanType.TCP_FIN: self.tcp_fin_scan,
            ScanType.TCP_XMAS: self.tcp_xmas_scan,
            ScanType.UDP: self.udp_scan,
        }
        
        method = scan_methods.get(scan_type, self.tcp_connect_scan)
        return method(target, port)
    
    def resolve_hostname(self, target: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            logger.error(f"Failed to resolve hostname: {target}")
            return None
    
    def reverse_dns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return None
