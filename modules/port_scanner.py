"""
NYX Framework - Advanced Port Scanner
High-performance multi-threaded port scanning
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
import time

from core.logger import get_logger
from core.scanner import AdvancedScanner, ScanType, ScanResult

logger = get_logger(__name__)

@dataclass
class PortRange:
    """Represents a range of ports"""
    start: int
    end: int
    
    def to_list(self) -> List[int]:
        return list(range(self.start, self.end + 1))

class PortScanner:
    """Advanced port scanner with multiple scanning techniques"""
    
    # Common port sets - Optimized for speed and effectiveness
    TOP_PORTS = {
        'top-20': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
        'top-100': [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157],
        'top-1000': list(range(1, 1001)),
        'web': [80, 81, 443, 591, 2082, 2087, 2095, 2096, 3000, 8000, 8001, 8008, 8080, 8083, 8443, 8834, 8888],
        'database': [1433, 1521, 3306, 5432, 5984, 6379, 7000, 7001, 8529, 9042, 9160, 27017, 27018, 27019, 28017],
        'all': list(range(1, 65536))
    }
    
    def __init__(self, args):
        self.args = args
        self.scanner = AdvancedScanner(args)
        self.threads = args.threads
        self.timeout = args.timeout
        
        # Determine scan type
        self.scan_type = self._determine_scan_type()
        
        # Parse port specification
        self.ports = self._parse_ports(args.ports if args.ports else 'top-100')
        
        logger.debug(f"Port scanner initialized: {len(self.ports)} ports, {self.threads} threads")
    
    def _determine_scan_type(self) -> ScanType:
        """Determine scan type based on arguments"""
        if self.args.syn:
            return ScanType.TCP_SYN
        elif self.args.connect:
            return ScanType.TCP_CONNECT
        elif self.args.udp:
            return ScanType.UDP
        elif self.args.null:
            return ScanType.TCP_NULL
        elif self.args.fin:
            return ScanType.TCP_FIN
        elif self.args.xmas:
            return ScanType.TCP_XMAS
        else:
            # Default based on mode
            if self.args.mode in ['stealth', 'paranoid']:
                return ScanType.TCP_SYN
            else:
                return ScanType.TCP_CONNECT
    
    def _parse_ports(self, port_spec: str) -> List[int]:
        """Parse port specification"""
        ports = []
        
        # Check if it's a predefined set
        if port_spec in self.TOP_PORTS:
            return self.TOP_PORTS[port_spec]
        
        # Parse custom specification
        for part in port_spec.split(','):
            part = part.strip()
            
            if '-' in part:
                # Range: 1-1000
                try:
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                except ValueError:
                    logger.warning(f"Invalid port range: {part}")
            else:
                # Single port
                try:
                    ports.append(int(part))
                except ValueError:
                    logger.warning(f"Invalid port: {part}")
        
        return sorted(set(ports))  # Remove duplicates and sort
    
    def scan(self, target: str, scan_params: Dict[str, Any]) -> Dict[str, Any]:
        """Scan target for open ports"""
        
        # Resolve target
        ip = self.scanner.resolve_hostname(target)
        if not ip:
            return {'error': 'Failed to resolve hostname'}
        
        # Calculate optimal threads for port range (limit for memory efficiency)
        max_threads_for_memory = 100  # Limit threads to reduce memory usage
        optimal_threads = min(self.threads, len(self.ports), scan_params.get('parallel', 50), max_threads_for_memory)
        
        logger.info(f"Scanning {target} ({ip}) - {len(self.ports)} ports with {optimal_threads} threads")
        logger.debug(f"Scan type: {self.scan_type.value}")
        
        start_time = time.time()
        
        # Randomize port order if specified
        ports_to_scan = self.ports.copy()
        if scan_params.get('randomize', False):
            import random
            random.shuffle(ports_to_scan)
        
        # Scan ports
        results = []
        open_ports = []
        filtered_ports = []
        closed_count = 0
        scanned_count = 0
        total_ports = len(ports_to_scan)
        
        # Progress tracking
        last_update = time.time()
        update_interval = 5.0  # Reduce update frequency to save resources
        
        # Get callbacks from scan_params
        progress_callback = scan_params.get('progress_callback')
        should_stop = scan_params.get('should_stop')
        
        with ThreadPoolExecutor(max_workers=optimal_threads) as executor:
            # Submit all port scans
            future_to_port = {
                executor.submit(self._scan_port_with_delay, ip, port, scan_params): port
                for port in ports_to_scan
            }
            
            # Collect results
            for future in as_completed(future_to_port):
                # Check for stop request
                if should_stop and should_stop():
                    logger.info("Scan stopped by user request")
                    break
                
                port = future_to_port[future]
                scanned_count += 1
                
                try:
                    result = future.result()
                    last_open_port = None
                    
                    if result.state == 'open':
                        open_ports.append(port)
                        results.append(asdict(result))
                        last_open_port = port
                        # Only show in terminal if not web mode
                        if not scan_params.get('web_mode', False):
                            logger.warning(f"  [{target}] Port {port}/tcp OPEN")
                    elif result.state == 'filtered':
                        filtered_ports.append(port)
                        # Only show filtered in verbose/debug mode and not web
                        if not scan_params.get('web_mode', False):
                            logger.debug(f"  [{target}] Port {port}/tcp filtered")
                    else:
                        closed_count += 1
                        # Never show closed ports (too noisy)
                    
                    # Call progress callback if provided
                    if progress_callback:
                        progress_callback(scanned_count, len(open_ports), last_open_port)
                    
                    # Show progress
                    current_time = time.time()
                    if current_time - last_update >= update_interval:
                        progress = (scanned_count / total_ports) * 100
                        elapsed = current_time - start_time
                        rate = scanned_count / elapsed if elapsed > 0 else 0
                        eta = (total_ports - scanned_count) / rate if rate > 0 else 0
                        
                        # Only show progress in terminal if not web mode
                        if not scan_params.get('web_mode', False):
                            logger.info(f"  Progress: {scanned_count}/{total_ports} ({progress:.1f}%) | "
                                      f"Rate: {rate:.0f} ports/sec | ETA: {eta:.0f}s | "
                                      f"Open: {len(open_ports)}")
                        last_update = current_time
                    
                except Exception as e:
                    logger.error(f"Error scanning port {port}: {e}")
        
        scan_time = time.time() - start_time
        avg_rate = total_ports / scan_time if scan_time > 0 else 0
        
        # Prepare results
        scan_results = {
            'target': target,
            'ip': ip,
            'scan_type': self.scan_type.value,
            'scan_time': scan_time,
            'scan_rate': avg_rate,
            'ports_scanned': len(self.ports),
            'open_ports': sorted(open_ports),
            'filtered_ports': filtered_ports,
            'closed_ports': closed_count,
            'port_details': results,
            'scan_params': scan_params
        }
        
        logger.info(f"Scan complete in {scan_time:.2f}s ({avg_rate:.0f} ports/sec): "
                   f"{len(open_ports)} open, {len(filtered_ports)} filtered, {closed_count} closed")
        
        return scan_results
    
    def _scan_port_with_delay(self, target: str, port: int, scan_params: Dict[str, Any]) -> ScanResult:
        """Scan a single port with timing delay"""
        
        # Apply timing delay
        if scan_params['delay'] > 0:
            import random
            delay = scan_params['delay']
            jitter = delay * random.uniform(-0.2, 0.2)
            time.sleep(delay + jitter)
        
        return self.scanner.scan_port(target, port, self.scan_type)
    
    def quick_scan(self, target: str) -> List[int]:
        """Quick scan of most common ports"""
        logger.info(f"Quick scan of {target}")
        
        # Scan only top 20 ports
        common_ports = self.TOP_PORTS['top-100'][:20]
        
        ip = self.scanner.resolve_hostname(target)
        if not ip:
            return []
        
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(self.scanner.tcp_connect_scan, ip, port): port
                for port in common_ports
            }
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    if result.state == 'open':
                        open_ports.append(port)
                except Exception as e:
                    logger.debug(f"Error in quick scan port {port}: {e}")
        
        return sorted(open_ports)
    
    def scan_specific_service(self, target: str, service: str) -> Optional[int]:
        """Scan for a specific service by name"""
        
        service_ports = {
            'ftp': [21],
            'ssh': [22],
            'telnet': [23],
            'smtp': [25, 587],
            'dns': [53],
            'http': [80, 8080, 8000, 8888],
            'https': [443, 8443],
            'smb': [139, 445],
            'mysql': [3306],
            'postgresql': [5432],
            'rdp': [3389],
            'vnc': [5900, 5901],
        }
        
        ports = service_ports.get(service.lower(), [])
        if not ports:
            logger.warning(f"Unknown service: {service}")
            return None
        
        ip = self.scanner.resolve_hostname(target)
        if not ip:
            return None
        
        for port in ports:
            result = self.scanner.tcp_connect_scan(ip, port)
            if result.state == 'open':
                logger.info(f"Found {service} on port {port}")
                return port
        
        return None
