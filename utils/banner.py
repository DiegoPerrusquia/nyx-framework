"""
NYX Framework - Banner Display
"""

import random

def display_banner(version: str):
    """Display ASCII banner"""
    
    banners = [
        r"""
    ███╗   ██╗██╗   ██╗██╗  ██╗
    ████╗  ██║╚██╗ ██╔╝╚██╗██╔╝
    ██╔██╗ ██║ ╚████╔╝  ╚███╔╝ 
    ██║╚██╗██║  ╚██╔╝   ██╔██╗ 
    ██║ ╚████║   ██║   ██╔╝ ██╗
    ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝
        """,
        r"""
    ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░  
    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
        """
    ]
    
    banner = random.choice(banners)
    
    print(f"\033[36m{banner}\033[0m")
    print(f"\033[32m    NYX Framework v{version} - Elite Reconnaissance Platform\033[0m")
    print(f"\033[33m    Advanced Network Reconnaissance & Enumeration Tool\033[0m")
    print(f"\033[90m    https://github.com/nyx-framework\033[0m")
    print()
    print(f"\033[31m    [!] Legal Warning: Only scan systems you have permission to test\033[0m")
    print()
