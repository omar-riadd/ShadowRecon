# ShadowRecon
## About
This script is an automated reconnaissance and vulnerability scanning pipeline designed for ethical security testing of web applications. Its core features include:

1. Anonymity & Evasion: All network requests and external tool executions are routed through Tor and ProxyChains to evade IP-based blocking and maintain anonymity.
2. IP Rotation: Automatically rotates the Tor exit IP upon encountering HTTP 403 (Forbidden) or 429 (Too Many Requests) status codes, or connection errors.
3. WAF Bypass Logic: Detects the target's WAF (Web Application Firewall) using wafw00f and runs targeted bypass payloads (e.g., Cloudflare, ModSecurity, Sucuri) before beginning the main scan.
4. Comprehensive Recon: Performs subdomain enumeration, live host probing, Wayback Machine scraping, and deep directory/parameter fuzzing.
5. Vulnerability Scanning: Pipelines parameterized URLs into popular tools like Dalfox, SQLMap, and FFuF for XSS, SQLi, and LFI/SSRF detection
## Prerequisites
This script requires several system packages and Go-based tools to be installed on your operating system (preferably Kali, Parrot, or a Debian/Ubuntu environment).
1. System Packages:
  The script's built-in check_tools function will guide you, but here are the primary system tools:
  - Python 3.x and pip install requests stem
  - Tor
  - ProxyChains
  - wafw00f
  - sqlmap
  - ffuf
  - waybackpy
  - dirsearch (or git clone it manually)
2. Go-Based Tools:
  Ensure you have Go installed and your GOBIN is in your $PATH.
  ```
  # Install Go tools
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install -v github.com/projectdiscovery/nuclei/cmd/nuclei@latest
  go install github.com/hahwul/dalfox/v2@latest
  # Optional: kxss
  go install github.com/tomnomnom/hacks/kxss@latest
  ```
## Configuration Setup (CRITICAL)
The script relies heavily on Tor running and ProxyChains routing traffic correctly.
1. Tor Setup:
  You must configure Tor to enable the Control Port for automatic IP rotation.

  1. Edit your Tor configuration file, typically /etc/tor/torrc.
  2. Add or uncomment the following lines:
       ```
       ControlPort 9051
       # IMPORTANT: Generate HashedControlPassword using 'tor --hash-password <your_password>'
       # Replace the example below with your actual hashed password
       HashedControlPassword 16:A6A92D73CFB42A...
       ```
   3. Crucially, set the plaintext password in the Python script: In the Python file, replace the placeholder password with the plaintext password you used to generate the hash
      ```
          # === In the Python script: ===
          TOR_CONTROL_PORT = 9051
          TOR_CONTROL_PASSWORD = "m06ahmed"  # <--- CHANGE THIS TO YOUR PLAINTEXT PASSWORD!
      ```
   4. Restart the Tor service
2. ProxyChains Setup
   This ensures all external tools use the local Tor SOCKS proxy
   1. Edit your ProxyChains configuration file, typically /etc/proxychains.conf.
   2. Ensure the last line specifies the Tor SOCKS proxy on port 9050:
        ```
        # ... (other config lines)
        # proxy list
        # add proxy here ...
        socks5  127.0.0.1 9050
        ```
## Usage
Running the Script:
You need to provide a target URL and a wordlist for directory brute-forcing
`python3 main.py -u <TARGET_URL> -w <WORDLIST_PATH>`
Flag -u with the full name -url is the Target URL (required). The root URL of the website to test for example like this one https://target.com/
Flag -w with the full name --wordlist is the Wordlist (required). Used for directory and file fuzzing (FFuF, Dirsearch) for example like this one ~/wordlists/medium.txt
Flag --lfi-payloads is the Optional list of payloads for LFI/SSRF fuzzing with FFuF for example like this one ~/wordlists/lfi-ssrf.txt
## Example
`python3 main.py -u https://my-personal-site.com -w /usr/share/wordlists/dirb/common.txt --lfi-payloads ~/payloads/lfi-payloads.txt`
