"""
NYX Framework - Evasion Manager
Implements advanced IDS/IPS evasion techniques
"""

import random
import time
from typing import Dict, List, Any
from dataclasses import dataclass

from core.logger import get_logger

logger = get_logger(__name__)

@dataclass
class EvasionProfile:
    """Evasion configuration profile"""
    name: str
    packet_delay: float  # Delay between packets in seconds
    fragment_packets: bool
    randomize_order: bool
    use_decoys: bool
    spoof_source: bool
    bad_checksums: bool
    ttl_manipulation: bool
    data_length_variation: bool
    description: str

class EvasionManager:
    """Manages evasion techniques to avoid detection"""
    
    PROFILES = {
        'none': EvasionProfile(
            name='none',
            packet_delay=0.0,
            fragment_packets=False,
            randomize_order=False,
            use_decoys=False,
            spoof_source=False,
            bad_checksums=False,
            ttl_manipulation=False,
            data_length_variation=False,
            description='No evasion - fastest but most detectable'
        ),
        'basic': EvasionProfile(
            name='basic',
            packet_delay=0.1,
            fragment_packets=False,
            randomize_order=True,
            use_decoys=False,
            spoof_source=False,
            bad_checksums=False,
            ttl_manipulation=False,
            data_length_variation=True,
            description='Basic evasion - reasonable speed and stealth'
        ),
        'advanced': EvasionProfile(
            name='advanced',
            packet_delay=0.5,
            fragment_packets=True,
            randomize_order=True,
            use_decoys=True,
            spoof_source=False,
            bad_checksums=False,
            ttl_manipulation=True,
            data_length_variation=True,
            description='Advanced evasion - slower but harder to detect'
        ),
        'maximum': EvasionProfile(
            name='maximum',
            packet_delay=2.0,
            fragment_packets=True,
            randomize_order=True,
            use_decoys=True,
            spoof_source=True,
            bad_checksums=True,
            ttl_manipulation=True,
            data_length_variation=True,
            description='Maximum evasion - very slow but nearly undetectable'
        )
    }
    
    # Timing templates (inspired by nmap)
    TIMING_TEMPLATES = {
        0: {'name': 'paranoid', 'delay': 5.0, 'timeout': 300, 'parallel': 1},
        1: {'name': 'sneaky', 'delay': 1.0, 'timeout': 60, 'parallel': 1},
        2: {'name': 'polite', 'delay': 0.4, 'timeout': 30, 'parallel': 1},
        3: {'name': 'normal', 'delay': 0.0, 'timeout': 10, 'parallel': 10},
        4: {'name': 'aggressive', 'delay': 0.0, 'timeout': 5, 'parallel': 50},
        5: {'name': 'insane', 'delay': 0.0, 'timeout': 1, 'parallel': 100}
    }
    
    def __init__(self, args):
        self.args = args
        
        # Load evasion profile
        self.profile = self.PROFILES.get(args.evasion, self.PROFILES['basic'])
        logger.info(f"Evasion profile: {self.profile.name} - {self.profile.description}")
        
        # Load timing template
        self.timing = self.TIMING_TEMPLATES.get(args.timing, self.TIMING_TEMPLATES[3])
        logger.info(f"Timing template: T{args.timing} ({self.timing['name']})")
        
        # Parse decoys if provided
        self.decoys = []
        if args.decoy:
            self.decoys = self._parse_decoys(args.decoy)
            logger.info(f"Using {len(self.decoys)} decoy address(es)")
        
        # Spoof source
        self.spoof_source = args.spoof_source
        if self.spoof_source:
            logger.warning(f"Source spoofing enabled: {self.spoof_source}")
        
        # Fragmentation
        self.fragment = args.fragment or self.profile.fragment_packets
        if self.fragment:
            logger.info("Packet fragmentation enabled")
        
        # Bad checksums
        self.badsum = args.badsum or self.profile.bad_checksums
        if self.badsum:
            logger.info("Bad checksum mode enabled (IDS evasion)")
    
    def _parse_decoys(self, decoy_str: str) -> List[str]:
        """Parse decoy addresses from comma-separated string"""
        decoys = []
        for decoy in decoy_str.split(','):
            decoy = decoy.strip()
            if decoy == 'RND':
                # Generate random IP
                decoys.append(self._generate_random_ip())
            elif decoy == 'ME':
                # Placeholder for actual source IP
                decoys.append('ME')
            else:
                decoys.append(decoy)
        return decoys
    
    def _generate_random_ip(self) -> str:
        """Generate a random IP address"""
        # Avoid reserved ranges
        octets = [
            random.randint(1, 223),
            random.randint(1, 254),
            random.randint(1, 254),
            random.randint(1, 254)
        ]
        return '.'.join(map(str, octets))
    
    def apply_evasion(self, target: str) -> Dict[str, Any]:
        """Apply evasion techniques and return scan parameters"""
        
        params = {
            'target': target,
            'delay': max(self.profile.packet_delay, self.timing['delay']),
            'timeout': self.timing['timeout'],
            'parallel': self.timing['parallel'],
            'fragment': self.fragment,
            'badsum': self.badsum,
            'randomize': self.profile.randomize_order,
            'decoys': self.decoys if self.profile.use_decoys else [],
            'spoof_source': self.spoof_source if self.profile.spoof_source else None,
            'ttl_variation': self.profile.ttl_manipulation,
            'data_length_variation': self.profile.data_length_variation
        }
        
        return params
    
    def apply_timing_delay(self):
        """Apply timing delay between operations"""
        delay = max(self.profile.packet_delay, self.timing['delay'])
        if delay > 0:
            # Add random jitter (±20%)
            jitter = delay * random.uniform(-0.2, 0.2)
            actual_delay = delay + jitter
            time.sleep(actual_delay)
    
    def randomize_port_order(self, ports: List[int]) -> List[int]:
        """Randomize port scanning order"""
        if self.profile.randomize_order or self.args.randomize_hosts:
            ports_copy = ports.copy()
            random.shuffle(ports_copy)
            return ports_copy
        return ports
    
    def get_ttl_value(self) -> int:
        """Get TTL value with optional variation"""
        if self.profile.ttl_manipulation:
            # Randomize TTL to evade detection
            return random.randint(64, 128)
        return 64  # Standard TTL
    
    def get_data_length(self, base_length: int = 0) -> int:
        """Get packet data length with optional variation"""
        if self.profile.data_length_variation:
            # Vary packet size
            return base_length + random.randint(-10, 50)
        return base_length
    
    def should_fragment(self, packet_size: int) -> bool:
        """Determine if packet should be fragmented"""
        if not self.fragment:
            return False
        
        # Fragment packets larger than 500 bytes
        return packet_size > 500
    
    def get_source_port(self) -> int:
        """Get source port (randomized or specific)"""
        # Common source ports that might bypass firewalls
        common_ports = [53, 80, 443, 20, 21, 22, 25, 53, 88, 110, 143, 993, 995]
        
        if random.random() < 0.3:  # 30% chance use common port
            return random.choice(common_ports)
        else:
            return random.randint(1024, 65535)
    
    def log_evasion_summary(self):
        """Log summary of evasion techniques in use"""
        logger.info("=== Evasion Techniques Summary ===")
        logger.info(f"Profile: {self.profile.name}")
        logger.info(f"Timing: T{self.args.timing} ({self.timing['name']})")
        logger.info(f"Packet Delay: {self.profile.packet_delay}s")
        logger.info(f"Fragmentation: {'Enabled' if self.fragment else 'Disabled'}")
        logger.info(f"Decoys: {len(self.decoys) if self.decoys else 'None'}")
        logger.info(f"Randomization: {'Enabled' if self.profile.randomize_order else 'Disabled'}")
        logger.info("=" * 35)
