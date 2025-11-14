"""
NYX Framework - Target Validator
Input validation and sanitization
"""

import re
import socket
import ipaddress
from typing import Optional

def validate_target(target: str) -> bool:
    """Validate target specification"""
    
    # Check if it's a valid IP address
    if is_valid_ip(target):
        return True
    
    # Check if it's a valid CIDR notation
    if is_valid_cidr(target):
        return True
    
    # Check if it's a valid hostname/domain
    if is_valid_hostname(target):
        return True
    
    # Check if it's a file path
    if is_file(target):
        return True
    
    return False

def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_cidr(cidr: str) -> bool:
    """Check if string is valid CIDR notation"""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False

def is_valid_hostname(hostname: str) -> bool:
    """Check if string is a valid hostname"""
    
    # Hostname regex pattern
    pattern = r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
    
    if re.match(pattern, hostname):
        return True
    
    # Try to resolve
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror:
        return False

def is_file(path: str) -> bool:
    """Check if string is a file path"""
    import os
    return os.path.isfile(path)

def sanitize_input(user_input: str) -> str:
    """Sanitize user input"""
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[;&|`$(){}[\]<>]', '', user_input)
    return sanitized.strip()

def validate_port(port: int) -> bool:
    """Validate port number"""
    return 1 <= port <= 65535

def validate_port_range(port_spec: str) -> bool:
    """Validate port range specification"""
    
    try:
        # Single port
        if port_spec.isdigit():
            return validate_port(int(port_spec))
        
        # Range
        if '-' in port_spec:
            start, end = map(int, port_spec.split('-'))
            return validate_port(start) and validate_port(end) and start <= end
        
        # Comma-separated
        if ',' in port_spec:
            ports = port_spec.split(',')
            return all(validate_port_range(p.strip()) for p in ports)
        
        return False
        
    except:
        return False
