XRecon - Advanced Reconnaissance Tool
Overview

XRecon is a sophisticated reconnaissance and information gathering tool tailored for security professionals, penetration testers, and ethical hackers. It streamlines the process of identifying subdomains, scanning open ports, extracting URLs, and collecting critical intelligence.
Features

    Subdomain Enumeration – Discover hidden subdomains associated with a target domain.
    Port Scanning – Identify open ports and running services efficiently.
    URL Extraction – Retrieve URLs from a specified target.
    Optimized Performance – Implements multithreading for enhanced speed.
    API Integrations – Leverages Shodan, VirusTotal, and other security intelligence platforms.

Installation

# Clone the repository
git clone https://github.com/yonathanpy/XRecon.git
cd XRecon

# Install dependencies
pip install -r requirements.txt

Usage

python xrecon.py -d target.com

Command-Line Options:

-d, --domain       Define the target domain
-s, --subdomains   Perform subdomain enumeration
-p, --ports        Execute a port scan
-u, --urls         Extract URLs
--shodan          Utilize Shodan API (API key required)

Example Execution:

python xrecon.py -d example.com -s -p -u

Disclaimer

This tool is strictly intended for professional security assessments and ethical hacking. Users must ensure lawful and authorized usage.
Future Enhancements

    Extended OSINT capabilities
    Advanced automation features
    Enhanced API integrations

Contributions are encouraged. Submit issues or pull requests to refine XRecon further.
