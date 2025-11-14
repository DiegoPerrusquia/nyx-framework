"""
NYX Framework - Logging System
Advanced logging with colored output and verbosity levels
"""

import logging
import sys
from datetime import datetime
from pathlib import Path

class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support"""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[92m',    # Bright Green (for open ports)
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'
    }
    
    SYMBOLS = {
        'DEBUG': '[*]',
        'INFO': '[+]',
        'WARNING': '[✓]',  # Checkmark for open ports
        'ERROR': '[x]',
        'CRITICAL': '[!!!]'
    }
    
    def __init__(self, use_color=True):
        self.use_color = use_color
        super().__init__()
    
    def format(self, record):
        if self.use_color:
            color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
            reset = self.COLORS['RESET']
            symbol = self.SYMBOLS.get(record.levelname, '[?]')
            
            timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
            
            return f"{color}{symbol}{reset} [{timestamp}] {record.getMessage()}"
        else:
            return f"[{record.levelname}] {record.getMessage()}"

def setup_logger(verbosity: int = 0, no_color: bool = False, silent: bool = False):
    """Setup root logger with appropriate verbosity"""
    
    # Determine log level based on verbosity and silent mode
    if silent:
        level = logging.ERROR  # Only show errors in silent mode
    elif verbosity == 0:
        level = logging.WARNING
    elif verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remove existing handlers
    root_logger.handlers = []
    
    # Console handler (skip if silent mode)
    if not silent:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(ColoredFormatter(use_color=not no_color))
        root_logger.addHandler(console_handler)
    
    # File handler for detailed logs (always enabled)
    log_dir = Path('./logs')
    log_dir.mkdir(exist_ok=True)
    
    log_file = log_dir / f"nyx_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)  # Always log everything to file
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    
    # Log the verbosity level
    if not silent:
        verb_msg = {
            0: "Normal output (warnings and errors)",
            1: "Verbose mode (info messages)",
            2: "Debug mode (all messages)",
        }
        root_logger.info(f"Logging level: {verb_msg.get(verbosity, 'Extra verbose')}")
    
    return root_logger

def get_logger(name: str):
    """Get a logger instance for a specific module"""
    return logging.getLogger(name)
