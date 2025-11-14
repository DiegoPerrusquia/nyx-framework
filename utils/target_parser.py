"""
NYX Framework - Target Parser
Parse and expand target specifications
"""

import ipaddress
from typing import List
from pathlib import Path

from core.logger import get_logger

logger = get_logger(__name__)

def parse_targets(target_spec: str, exclude_spec: str = None) -> List[str]:
    """Parse target specification into list of targets"""
    
    targets = []
    
    # Check if it's a file
    if Path(target_spec).is_file():
        targets = _parse_target_file(target_spec)
    
    # Check if it's CIDR notation
    elif '/' in target_spec:
        targets = _expand_cidr(target_spec)
    
    # Check if it's a range (e.g., 192.168.1.1-10)
    elif '-' in target_spec and '.' in target_spec:
        targets = _expand_range(target_spec)
    
    # Single target (IP or hostname)
    else:
        targets = [target_spec]
    
    # Apply exclusions
    if exclude_spec:
        excluded = parse_targets(exclude_spec)
        targets = [t for t in targets if t not in excluded]
    
    logger.debug(f"Parsed {len(targets)} target(s)")
    
    return targets

def _parse_target_file(filepath: str) -> List[str]:
    """Parse targets from file"""
    
    targets = []
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Recursively parse each line
                parsed = parse_targets(line)
                targets.extend(parsed)
        
        logger.info(f"Loaded {len(targets)} target(s) from file")
        
    except Exception as e:
        logger.error(f"Error reading target file: {e}")
    
    return targets

def _expand_cidr(cidr: str) -> List[str]:
    """Expand CIDR notation to individual IPs"""
    
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        
        # Limit expansion to reasonable size
        if network.num_addresses > 65536:
            logger.warning(f"CIDR {cidr} contains {network.num_addresses} addresses - limiting to first 65536")
            hosts = list(network.hosts())[:65536]
        else:
            hosts = list(network.hosts())
        
        return [str(ip) for ip in hosts]
        
    except ValueError as e:
        logger.error(f"Invalid CIDR notation: {cidr}")
        return []

def _expand_range(range_spec: str) -> List[str]:
    """Expand IP range (e.g., 192.168.1.1-10)"""
    
    try:
        # Split on the last dash
        parts = range_spec.rsplit('-', 1)
        if len(parts) != 2:
            return [range_spec]
        
        base_ip = parts[0]
        end_octet = int(parts[1])
        
        # Get the octets
        octets = base_ip.split('.')
        if len(octets) != 4:
            return [range_spec]
        
        start_octet = int(octets[-1])
        base = '.'.join(octets[:-1])
        
        # Generate range
        ips = []
        for i in range(start_octet, end_octet + 1):
            if 0 <= i <= 255:
                ips.append(f"{base}.{i}")
        
        return ips
        
    except Exception as e:
        logger.error(f"Error parsing range: {range_spec}")
        return [range_spec]

def parse_ports(port_spec: str) -> List[int]:
    """Parse port specification"""
    
    ports = []
    
    for part in port_spec.split(','):
        part = part.strip()
        
        if '-' in part:
            # Range
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
    
    return sorted(set(ports))
