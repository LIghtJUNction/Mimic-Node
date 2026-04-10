#!/usr/bin/env python3
"""
Fetch and test domains for Reality SNI compatibility.
Reads domain lists from Clash/V2Ray community sources, tests each domain
for TLS 1.3 + ALPN h2 support using openssl, and outputs compatible domains.
"""

import subprocess
import os
import re
from typing import Set, Tuple, Optional, Dict
import concurrent.futures
import argparse
import json
import time

# Domain sources - from Loyalsoldier's v2ray-rules-dat releases
# These are in the release assets, not the repo

# We'll fetch the latest release tag dynamically
def get_latest_release_tag() -> str:
    """Get the latest release tag from Loyalsoldier/v2ray-rules-dat."""
    import urllib.request
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest",
            headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            import json
            data = json.loads(response.read())
            return data.get('tag_name', '202604072233')
    except Exception:
        return '202604072233'  # fallback to known tag

# Additional hardcoded high-quality domains (always tested first)
# Criteria: International large sites + accessible from mainland China
# 符合条件：Apple, Microsoft, Amazon, Cloudflare, PayPal, Shopify, Slack, Zoom, etc.
# 这些域名经过人工验证，适合作为 Reality SNI
EXTRA_DOMAINS = """swdist.apple.com
www.apple.com
www.icloud.com
www.microsoft.com
www.office.com
www.outlook.com
login.live.com
www.bing.com
www.visualstudio.com
code.visualstudio.com
www.amazonaws.com
signin.aws.amazon.com
portal.azure.com
cloud.google.com
www.cloudflare.com
www.amazon.com
www.paypal.com
www.shopify.com
www.slack.com
www.zoom.us
www.dropbox.com
www.box.com
www.atlassian.com
www.salesforce.com
www.skyscanner.net
www.booking.com
www.stripe.com
www.reddit.com
github.com
www.github.com
www.youtube.com
www.linkedin.com
www.netflix.com
www.spotify.com
www.discord.com
www.openai.com
www.telegram.org
www.cloudflare.com
www.akamai.com
www.fastly.com
"""

# TLDs to exclude (China-based or problematic)
EXCLUDE_TLDS = {
    # China and related
    '.cn', '.tw', '.hk', '.mo',
    # Russia and CIS
    '.ru', '.su', '.by', '.kz', '.kg', '.tj', '.tm', '.uz',
    # Iran
    '.ir',
    # North Korea
    '.kp',
    # Syria
    '.sy',
    # Cuba
    '.cu',
    # Venezuela
    '.ve',
    # Short link / url shortener TLDs (not useful for SNI)
    '.ly', '.to', '.be', '.gg', '.me', '.cc', '.io', '.co', '.im', '.gs',
    # Other ccTLDs that add no entropy
    '.sb', '.tv', '.vc', '.ms', '.mu', '.sb',
}

# Known China-based or China-affiliated domains to exclude
EXCLUDE_KEYWORDS = {
    'baidu', 'alibaba', 'taobao', 'tmall', 'alipay', 'antgroup',
    'tencent', 'qq.com', 'wechat', 'weixin', 'tencentcloud',
    'jd.com', 'pinduoduo', 'meituan', '.cn$',
    '360.cn', 'so.com', 'sina', 'weibo', 'zhihu', 'bilibili',
    'youku', 'iqiyi', 'migu', 'music', 'netease',
    'xiaomi', 'mi.com', 'redmi', 'huawei', 'honor', 'oppo', 'vivo', 'oneplus', 'realme',
    'lenovo', '.gov.cn', 'edu.cn',
    '163.com', '126.com', 'mail', 'aliyun', 'dingtalk',
    'suning', 'coupon', 'ctrip', 'qunar', 'fliggy', 'hotel',
    'didi', 'grab', 'gojek', 'line',
    # Google country TLDs - too obvious, reveals Google infrastructure
    'google.ad', 'google.ae', 'google.al', 'google.am', 'google.as',
    'google.at', 'google.az', 'google.ba', 'google.be', 'google.bf',
    'google.bg', 'google.bi', 'google.bj', 'google.bs', 'google.bt',
    'google.by', 'google.ca', 'google.cd', 'google.cf', 'google.cg',
    'google.ci', 'google.cl', 'google.cm', 'google.cn', 'google.co',
    'google.cv', 'google.cz', 'google.de', 'google.dj', 'google.dk',
    'google.dm', 'google.dz', 'google.ee', 'google.es', 'google.et',
    'google.fi', 'google.fm', 'google.fr', 'google.ga', 'google.ge',
    'google.gg', 'google.gl', 'google.gm', 'google.gp', 'google.gr',
    'google.gy', 'google.hk', 'google.hn', 'google.hr', 'google.ht',
    'google.hu', 'google.ie', 'google.im', 'google.iq', 'google.is',
    'google.it', 'google.je', 'google.jo', 'google.jp', 'google.ke',
    'google.ki', 'google.kz', 'google.la', 'google.li', 'google.lk',
    'google.lt', 'google.lu', 'google.lv', 'google.md', 'google.me',
    'google.mg', 'google.mk', 'google.ml', 'google.mn', 'google.ms',
    'google.mt', 'google.mu', 'google.mv', 'google.mw', 'google.mx',
    'google.my', 'google.na', 'google.ne', 'google.nl', 'google.no',
    'google.nr', 'google.nu', 'google.nz', 'google.pl', 'google.pn',
    'google.ps', 'google.pt', 'google.ro', 'google.rs', 'google.rw',
    'google.sc', 'google.se', 'google.sh', 'google.si', 'google.sk',
    'google.sm', 'google.sn', 'google.so', 'google.sr', 'google.st',
    'google.td', 'google.tg', 'google.tl', 'google.tm', 'google.tn',
    'google.to', 'google.tt', 'google.vg', 'google.vu', 'google.ws',
    # Facebook/Meta typos and variants
    'facboo', 'faebok', 'fb.careers', 'fbhome', 'fb.me', 'fb.gg',
    'fbsbx', 'fbcdn', 'fburl', 'fbidb',
    # Typo domains (google)
    'gogle.com', 'googel.com', 'gogole.com', 'googil.com', 'googlr.com',
    'goolge.com', 'gogle.', 'googel.', 'googil.', 'googlr.',
    'foofle.com', 'foofoo.com',
    # Short link / redirect services
    'do.co', 'dis.gd', 'adbq.fr', 'link.com', 'pdf.new', 'docs.new',
    'meet.new', 'shop.app', 'sign.new', 'whats.new', 'redd.it',
    'youtu.be', 'on.here', 'on2.com', 'run.app', 'web.app',
    # Google shortlinks / Firebase
    'page.link', 'pages.dev', 'app.link',
    # Suspicious or known tracking/ad domains
    '466453.com', 'admeld.com', 'apture.com', 'atdmt2.com', 'binads.com',
    'bumptop.ca', 'crixet.com', 'coova.com', 'coova.net', 'coova.org',
    # Alexa/customer
    'alexa.com', 'alexa.',
    # graph.org (suspicious)
    'graph.org',
    # tfhub.dev (often used for TensorFlow demos)
    'tfhub.dev',
    # Free URL redirects that add no SNI entropy
    'freeb.com',
    # Facebook/Meta typo domains (all variants of facebook typo squats)
    'acebook.com', 'facbeok.com', 'facebof.com', 'facebok.com', 'facebol.com',
    'facebuk.com', 'faceobk.com', 'faceook.com', 'faebook.com', 'faycbok.com',
    'fcebook.com', 'feacboo.com', 'fecbbok.com', 'fecbooc.com', 'fecbook.com',
    'fbookk.com', 'facbook.com', 'facebok.com', 'faceb0ok.com',
    'faccebook.com', 'facerbook.com', 'facesbook.com', 'factbook.com',
    'favebook.com', 'fcaebook.com',
    # Google typos and dead services
    'googl.com', 'googlee.com', 'froogle.com',
    # Suspicious dead/experimental Google domains
    'fuchsia.dev', 'stadia.dev', ' Area120', 'area120.com',
    'verily.com', 'saynow.com', 'picnik.com', 'picasa.com',
    # Suspicious redirect or single-word .com domains
    'chat.com', 'live.com', 'waze.com', 'xoom.com', 'nest.com',
    'repo.new', 'sora.com', 'nxta.org', 'ton.org',
    # Other experimental/dead services
    'bumptop.com', 'bumptop.net', 'bumptop.ca',
    'gigjam.com', 'revolv.com', 'shazam.com', 'redkix.com',
    'telega.one', 'wallet.com', 'winhec.com', 'winhec.net',
    'yammer.com', 'oauthz.com', 'ccnsite.com',
    # Google Workspace experiment domains
    'gsuite.com', 'googlee.com',
    # Microsoft internal/redirect
    'hwgo.com', 'mepn.com',
    # Ad/tracking domains
    'ingads.com', 'brotli.org',
    # OpenAI typo
    'chatgpt.com',
    # Google internal
    'j2objc.org', 'webrtc.org', 'oauthz.com',
}

# Known good domains by region (prioritized by server location awareness)
# Format: (domain, region_hint) where region_hint is one of: us, eu, ap, global
# Criteria: International large sites + accessible from mainland China
KNOWN_GOOD = {
    # Apple (global)
    ('swdist.apple.com', 'global'),
    ('www.apple.com', 'global'),
    ('www.icloud.com', 'global'),
    # Microsoft (global)
    ('www.microsoft.com', 'global'),
    ('www.office.com', 'global'),
    ('www.outlook.com', 'global'),
    ('login.live.com', 'global'),
    ('www.bing.com', 'global'),
    ('www.visualstudio.com', 'global'),
    ('code.visualstudio.com', 'global'),
    # AWS/Azure/GCP (global)
    ('www.amazonaws.com', 'global'),
    ('signin.aws.amazon.com', 'global'),
    ('portal.azure.com', 'global'),
    ('cloud.google.com', 'global'),
    # Cloudflare (global)
    ('www.cloudflare.com', 'global'),
    # Amazon (global)
    ('www.amazon.com', 'global'),
    # PayPal (global)
    ('www.paypal.com', 'global'),
    # Shopify (global)
    ('www.shopify.com', 'global'),
    # Slack (global)
    ('www.slack.com', 'global'),
    # Zoom (global)
    ('www.zoom.us', 'global'),
    # Dropbox (global)
    ('www.dropbox.com', 'global'),
    # Box (global)
    ('www.box.com', 'global'),
    # Atlassian (global)
    ('www.atlassian.com', 'global'),
    # Salesforce (global)
    ('www.salesforce.com', 'global'),
    # EU-focused
    ('www.skyscanner.net', 'eu'),
    ('www.booking.com', 'eu'),
    # Stripe (global)
    ('www.stripe.com', 'global'),
    # Reddit (global - though partially blocked)
    ('www.reddit.com', 'global'),
}


def is_valid_domain(domain: str) -> bool:
    """Check if domain looks valid and worth testing."""
    domain = domain.lower().strip()

    # Must not be empty
    if not domain:
        return False

    # Must contain at least one dot (not just TLD)
    if '.' not in domain:
        return False

    # Skip leading dot
    domain = domain.lstrip('.')

    # Skip internationalized domain names (contain non-ASCII)
    try:
        domain.encode('ascii')
    except UnicodeEncodeError:
        return False

    parts = domain.split('.')

    # Skip very short second-level domains (e.g., "a.co", "x.io" are suspicious)
    if len(parts) >= 2:
        sld = parts[-2]  # second-level domain
        if len(sld) < 3:
            return False
        # Skip domains that are pure numbers or mostly numbers
        if sld.isdigit():
            return False

    # Skip TLDs that are too country-specific or problematic
    for tld in EXCLUDE_TLDS:
        if domain.endswith(tld):
            return False

    # Skip domains with problematic keywords
    domain_lower = domain.lower()
    for keyword in EXCLUDE_KEYWORDS:
        if keyword in domain_lower:
            return False

    # Skip domains with unusual characters
    if not re.match(r'^[a-z0-9.\-_]+$', domain):
        return False

    # Skip very long domains
    if len(domain) > 100:
        return False

    # Skip known bad patterns
    bad_patterns = ['.onion', '.i2p', '.bit', '.exit:', '127.0.0', 'localhost']
    for pattern in bad_patterns:
        if pattern in domain:
            return False

    # Skip domains with google. prefix that aren't google.com (captures google.md etc)
    if domain.startswith('google.') and domain != 'google.com':
        return False

    # Skip domains with too many hyphens (suspicious subdomain chains)
    if domain.count('-') > 3:
        return False

    # Skip very short TLDs that are just redirects (< 3 chars, excluding common ones)
    tld = parts[-1]
    if len(tld) <= 2 and tld not in ('com', 'net', 'org', 'gov', 'edu', 'mil'):
        return False

    return True


def get_server_region() -> str:
    """
    Detect server region by querying IP geolocation.
    Returns: 'us', 'eu', 'ap' (asia-pacific), or 'unknown'
    """
    try:
        import urllib.request
        # Use ipapi.co to get location (free, no API key needed)
        req = urllib.request.Request(
            "https://ipapi.co/json/",
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            import json
            data = json.loads(response.read())
            country = data.get('country_code', '')
            # Map country to region
            if country in ('US', 'CA', 'MX'):
                return 'us'
            elif country in ('GB', 'DE', 'FR', 'NL', 'SE', 'NO', 'DK', 'FI', 'PL', 'IT', 'ES', 'PT'):
                return 'eu'
            elif country in ('JP', 'KR', 'SG', 'HK', 'TW', 'AU', 'NZ', 'IN', 'TH', 'VN', 'MY', 'PH', 'ID', 'MY'):
                return 'ap'
            else:
                return 'unknown'
    except Exception:
        return 'unknown'


def parse_domains_from_line(line: str) -> Set[str]:
    """Parse domain(s) from a line in geosite format."""
    line = line.strip()

    # Skip comments and empty lines
    if not line or line.startswith('#'):
        return set()

    domains = set()

    # Handle various formats:
    # full:example.com -> example.com
    # domain:example.com -> example.com
    # keyword:google -> skip (too broad)
    # include:other-category -> skip (recursive, handled separately)
    # or just plain domain.com

    if ':' in line:
        prefix, rest = line.split(':', 1)
        rest = rest.strip()
        # Only accept 'full' and 'domain' types, skip 'keyword', 'pattern', 'include', etc.
        if prefix in ('full', 'domain'):
            if is_valid_domain(rest):
                domains.add(rest)
    else:
        # Plain domain
        if is_valid_domain(line):
            domains.add(line)

    return domains


def fetch_domain_list(url: str) -> Set[str]:
    """Fetch a domain list from URL and extract domains."""
    domains = set()
    try:
        import urllib.request
        import urllib.error
        print(f"  Fetching: {url}")
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as response:
            content = response.read().decode('utf-8', errors='ignore')
            for line in content.split('\n'):
                domains.update(parse_domains_from_line(line))
    except Exception as e:
        print(f"  Warning: Failed to fetch {url}: {e}")
    return domains


def load_extra_domains() -> Set[str]:
    """Load extra hardcoded domains."""
    domains = set()
    for line in EXTRA_DOMAINS.strip().split('\n'):
        line = line.strip()
        if line and is_valid_domain(line):
            domains.add(line.lower())
    return domains


def get_known_good_by_region(region: str) -> list:
    """Get known good domains, sorted by relevance to region."""
    global KNOWN_GOOD

    # Split into regional and global
    global_domains = []

    for domain_tuple in KNOWN_GOOD:
        if isinstance(domain_tuple, tuple):
            domain, domain_region = domain_tuple
        else:
            domain = domain_tuple
            domain_region = 'global'

        if is_valid_domain(domain):
            if domain_region == region or domain_region == 'global':
                global_domains.append(domain)
            elif region == 'unknown':
                # If we can't detect region, include everything
                global_domains.append(domain)

    return global_domains


# ─── Domain Valuation ────────────────────────────────────────────────

HUMBLEWORTH_MODEL = "llamasrc-ai/humbleworth"
HUMBLEWORTH_VERSION = "7ypeqnlkkedzre6wesapb3kel66rkx3qjm2q3k3cje5z3qmmm65cq"


def extract_value(text: str) -> Optional[float]:
    """Extract a dollar amount from HumbleWorth output text."""
    text = text.strip()
    # Try to find a dollar amount
    patterns = [
        r'\$([0-9,]+(?:\.[0-9]+)?)',
        r'worth.*?\$([0-9,]+)',
        r'\$([0-9,]+)',
        r'value.*?([0-9,]+)',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            val = m.group(1).replace(',', '')
            try:
                v = float(val)
                # Sanity check: skip absurdly low values (< $10) as noise
                if v >= 10:
                    return v
            except ValueError:
                pass
    return None


def get_humbleworth_value(domain: str, api_token: str, timeout: float = 30.0) -> Tuple[str, Optional[float]]:
    """
    Call HumbleWorth on Replicate to get domain valuation.
    Returns (domain, value_in_dollars or None).
    """
    try:
        import urllib.request
        import urllib.error

        url = "https://predict.replicate.com/v1/predictions"
        payload = {
            "version": HUMBLEWORTH_VERSION,
            "input": {"domain": domain}
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={
                'Authorization': f'Token {api_token}',
                'Content-Type': 'application/json',
            },
            method='POST'
        )

        with urllib.request.urlopen(req, timeout=timeout) as resp:
            prediction = json.loads(resp.read())
            pred_id = prediction.get('id')
            status = prediction.get('status')

        # Poll for completion
        get_url = f"https://predict.replicate.com/v1/predictions/{pred_id}"
        for _ in range(60):  # up to 60 * 2s = 120s
            time.sleep(2)
            req2 = urllib.request.Request(get_url, headers={'Authorization': f'Token {api_token}'})
            with urllib.request.urlopen(req2, timeout=timeout) as resp:
                prediction = json.loads(resp.read())
            status = prediction.get('status')
            if status == 'succeeded':
                output = prediction.get('output', '')
                if isinstance(output, list):
                    output = ' '.join(str(o) for o in output)
                value = extract_value(str(output))
                return (domain, value)
            elif status in ('failed', 'canceled'):
                break
    except Exception:
        pass
    return (domain, None)


def get_domainindex_value(domain: str, api_key: str, timeout: float = 10.0) -> Tuple[str, Optional[float]]:
    """
    Call DomainIndex appraisal API.
    Returns (domain, estimated_value_usd or None).
    """
    try:
        import urllib.request
        import urllib.parse

        params = urllib.parse.urlencode({
            'action': 'appraise',
            'domain': domain,
            'mode': 'json',
            'key': api_key,
        })
        url = f"https://domainindex.com/api.php?{params}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            # Try to extract price
            if isinstance(data, dict):
                price = data.get('price') or data.get('valuation') or data.get('estimated_value')
                if price:
                    try:
                        return (domain, float(price))
                    except (ValueError, TypeError):
                        pass
    except Exception:
        pass
    return (domain, None)


def score_domain(domain: str, valuations: Dict[str, Optional[float]]) -> float:
    """
    Score a domain based on valuation results from multiple APIs.
    Returns the best (max) valuation in USD, or 0 if no valuations succeeded.
    Higher score = more valuable domain.
    """
    scores = []
    for source, value in valuations.items():
        if value is not None and value >= 10:
            scores.append(value)
    if not scores:
        return 0.0
    return max(scores)


# ─── TLS Test ────────────────────────────────────────────────────────

def test_domain_openssl(domain: str, timeout: float = 5.0) -> Tuple[str, bool]:
    """
    Test if domain supports TLS 1.3 with ALPN h2 using openssl.
    Returns (domain, True) if compatible, (domain, False) otherwise.
    """
    try:
        # Use echo to immediately close the connection after TLS handshake
        result = subprocess.run(
            ['sh', '-c', f"echo | openssl s_client -connect {domain}:443 -alpn h2 -tls1_3 -servername {domain} 2>&1 | grep -i 'ALPN protocol: h2'"],
            capture_output=True,
            timeout=timeout,
            text=True
        )
        if result.returncode == 0 and 'alpn protocol: h2' in result.stdout.lower():
            return (domain, True)
        return (domain, False)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        return (domain, False)


def main():
    parser = argparse.ArgumentParser(description='Fetch and test domains for Reality SNI')
    parser.add_argument('--max-domains', type=int, default=500,
                        help='Maximum number of domains to test (default: 500)')
    parser.add_argument('--threads', type=int, default=20,
                        help='Number of parallel test threads (default: 20)')
    parser.add_argument('--output', '-o', type=str, default='sni.txt',
                        help='Output file path (default: sni.txt)')
    parser.add_argument('--sources-only', action='store_true',
                        help='Only fetch sources, do not test domains')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    parser.add_argument('--valuation-threshold', type=float, default=100.0,
                        help='Minimum domain valuation (USD) to include (default: 100)')
    parser.add_argument('--max-val-domains', type=int, default=200,
                        help='Max domains to send for valuation (default: 200)')
    args = parser.parse_args()

    print("=" * 60)
    print("Reality SNI Domain Fetcher")
    print("=" * 60)
    print()

    # Step 1: Fetch domains from all sources
    print("[1/4] Fetching domain lists...")
    all_domains = set()

    # Detect server region
    region = get_server_region()
    print(f"  Detected server region: {region.upper()}")

    # Add regional + global known good domains first (highest priority)
    known_good_domains = get_known_good_by_region(region)
    all_domains.update(known_good_domains)
    print(f"  Added {len(known_good_domains)} known good domains (region-matched)")

    # Add extra hardcoded domains
    extra_domains = load_extra_domains()
    all_domains.update(extra_domains)
    print(f"  Added {len(extra_domains)} extra hardcoded domains")

    # NOTE: v2fly/domain-list-community sources disabled.
    # Their facebook/google/apple lists are heavily polluted with typo-squat domains
    # (e.g. facbeok.com, google.al, etc.) that are useless for Reality SNI.
    # Using only KNOWN_GOOD + EXTRA_DOMAINS which are human-curated.
    # To re-enable, you'd need to add extensive keyword filtering for each category.
    pass

    print(f"  Total unique domains after fetching: {len(all_domains)}")

    # Step 2: Filter and validate
    print("[2/5] Filtering domains...")
    valid_domains = set()
    for domain in all_domains:
        if is_valid_domain(domain):
            valid_domains.add(domain.lower().strip())

    # Prioritize known good domains (region-matched)
    prioritized = []
    remaining = []
    known_good_set = set(known_good_domains)
    for d in valid_domains:
        if d in known_good_set:
            prioritized.append(d)
        else:
            remaining.append(d)

    # Sort remaining by domain length (shorter = more general = better)
    remaining.sort(key=lambda x: (len(x), x))
    prioritized.sort()

    final_domains = prioritized + remaining

    # Limit domains to test
    if len(final_domains) > args.max_domains:
        print(f"  Limiting to {args.max_domains} domains")
        final_domains = final_domains[:args.max_domains]

    print(f"  Total domains to test: {len(final_domains)}")

    if args.sources_only:
        print("\n[SOURCES ONLY] Skipping domain testing.")
        with open(args.output, 'w') as f:
            for domain in sorted(final_domains):
                f.write(domain + '\n')
        print(f"Written {len(final_domains)} domains to {args.output}")
        return

    # Step 3: Test domains with openssl
    print("[3/5] Testing domains with TLS 1.3 + ALPN h2...")
    compatible_domains = []
    tested = 0
    total = len(final_domains)

    # Use thread pool for parallel testing
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_domain = {
            executor.submit(test_domain_openssl, domain): domain
            for domain in final_domains
        }

        for future in concurrent.futures.as_completed(future_to_domain):
            tested += 1
            domain, is_compatible = future.result()
            if is_compatible:
                compatible_domains.append(domain)
                print(f"\r  Progress: {tested}/{total} | Compatible: {len(compatible_domains)}", end='', flush=True)
            else:
                print(f"\r  Progress: {tested}/{total} | Compatible: {len(compatible_domains)}", end='', flush=True)

    print()
    print()

    # Step 4: Domain valuation
    # Get API keys from environment; graceful no-op if not set
    replicate_token = os.environ.get('REPLICATE_API_TOKEN', '')
    domainindex_key = os.environ.get('DOMAININDEX_API_KEY', '')

    valuation_threshold = args.valuation_threshold
    max_val_budget = getattr(args, 'max_val_domains', 200)

    if not replicate_token and not domainindex_key:
        print("[4/6] Domain valuation skipped (no API keys set)")
        print("  Set REPLICATE_API_TOKEN and/or DOMAININDEX_API_KEY to enable")
        high_value_domains = compatible_domains
        domain_scores: Dict[str, float] = {}
    elif not compatible_domains:
        high_value_domains = []
        domain_scores = {}
    else:
        # Decide how many domains to valuate (budget cap)
        val_targets = compatible_domains[:max_val_budget]
        print(f"[4/6] Domain valuation ({len(val_targets)} domains, threshold=${valuation_threshold})...")

        valuations: Dict[str, Dict[str, Optional[float]]] = {
            d: {} for d in val_targets
        }
        val_done = 0
        val_total = len(val_targets)

        def val_worker(domain: str) -> Tuple[str, Dict[str, Optional[float]]]:
            result = {}
            # HumbleWorth (Replicate)
            if replicate_token:
                _, val = get_humbleworth_value(domain, replicate_token)
                result['humbleworth'] = val
            # DomainIndex
            if domainindex_key:
                _, val2 = get_domainindex_value(domain, domainindex_key)
                result['domainindex'] = val2
            return (domain, result)

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(val_worker, d): d for d in val_targets}
            for future in concurrent.futures.as_completed(futures):
                domain, result = future.result()
                valuations[domain] = result
                val_done += 1
                print(f"\r  Valuation progress: {val_done}/{val_total}", end='', flush=True)

        print()
        print()

        # Score each domain
        domain_scores = {}
        for domain, vals in valuations.items():
            domain_scores[domain] = score_domain(domain, vals)

        # Filter by threshold
        high_value_domains = [
            d for d in compatible_domains
            if domain_scores.get(d, 0) >= valuation_threshold
        ]
        print(f"[5/6] Valuation filtering (>= ${valuation_threshold})...")
        print(f"  Domains above threshold: {len(high_value_domains)}")

    # Step 6: Write output
    print("[6/6] Writing results...")
    high_value_domains.sort(key=lambda x: (domain_scores.get(x, 0), len(x), x), reverse=True)

    with open(args.output, 'w') as f:
        for domain in high_value_domains:
            f.write(domain + '\n')

    print(f"  Final domains: {len(high_value_domains)}")
    print(f"  Output written to: {args.output}")

    # Print summary
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print("  External sources checked: 0 (v2fly disabled due to noise)")
    print(f"  Domains collected: {len(all_domains)}")
    print(f"  Domains tested (TLS 1.3+ALPN h2): {len(final_domains)}")
    print(f"  TLS compatible: {len(compatible_domains)}")
    print(f"  Above valuation threshold (>= ${valuation_threshold}): {len(high_value_domains)}")
    if high_value_domains:
        print("\n  Top 10 high-value domains:")
        for d in high_value_domains[:10]:
            score = domain_scores.get(d, 0)
            print(f"    - {d}  (${score:.2f})" if score > 0 else f"    - {d}")


if __name__ == '__main__':
    main()
