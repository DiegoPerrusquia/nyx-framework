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
    ////////////////////////////////////////
    //oooo   oooo ooooo  oooo ooooo  oooo //
    // 8888o  88    888  88     888  88   //
    // 88 888o88      888         888     //
    // 88   8888      888        88 888   //
    //o88o    88     o888o    o88o  o888o //
    ////////////////////////////////////////
        """,
        r"""
    .-._                              ,-.--,
    /==/ \  .-._ ,--.-.  .-,--.--.-.  /=/, .'
    |==|, \/ /, /==/- / /=/_ /\==\ -\/=/- /  
    |==|-  \|  |\==\, \/=/. /  \==\ `-' ,/   
    |==| ,  | -| \==\  \/ -/    |==|,  - |   
    |==| -   _ |  |==|  ,_/    /==/   ,   \  
    |==|  /\ , |  \==\-, /    /==/, .--, - \ 
    /==/, | |- |  /==/._/     \==\- \/=/ , / 
    `--`./  `--`  `--`-`       `--`-'  `--`  
        """
    ]
    
    banner = random.choice(banners)
    
    print(f"\033[36m{banner}\033[0m")
    print(f"\033[32m    NYX Scanner v{version} - Network Reconnaissance Tool\033[0m")
    print(f"\033[33m    Lightweight Port Scanner & Service Detection\033[0m")
    print(f"\033[90m    https://github.com/DiegoPerrusquia/nyx-framework\033[0m")
    print()
    print(f"\033[31m    [!] Legal Warning: Only scan systems you have permission to test\033[0m")
    print()