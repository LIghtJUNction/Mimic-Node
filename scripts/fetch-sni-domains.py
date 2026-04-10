#!/usr/bin/env python3
"""
Fetch and test domains for Reality SNI compatibility.
Reads domain lists from Clash/V2Ray community sources, tests each domain
for TLS 1.3 + ALPN h2 support using openssl, and outputs compatible domains.
"""

import subprocess
import sys
import os
import re
import tempfile
import hashlib
from datetime import datetime
from typing import Set, Tuple
import concurrent.futures
import argparse

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
www.ebay.com
www.reddit.com
github.com
www.github.com
www.google.com
www.facebook.com
www.youtube.com
www.instagram.com
www.twitter.com
www.linkedin.com
www.netflix.com
www.spotify.com
www.tiktok.com
www.amazon.com
www.apple.com
www.microsoft.com
www.cloudflare.com
www.atlassian.com
www.shopify.com
www.slack.com
www.dropbox.com
www.zoom.us
www.paypal.com
www.stripe.com
www.salesforce.com
www.cloudflare.com
"""

# TLDs to exclude (China-based or problematic)
EXCLUDE_TLDS = {
    # China and related
    '.cn', '.tw', '.hk', '.mo',
    # Middle East
    '.saudi', '.ae', '.qa', '.kw', '.om', '.bh', '.iq', '.jo', '.lb', '.sy', '.yi',
    # Russia and CIS
    '.ru', '.su', '.by', '.kz', '.kg', '.tj', '.tm', '.uz',
    # Iran
    '.ir', '.ae',
    # Other problematic
    '.kp', '.sy', '.cu', '.ve',
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
    '163.com', '126.com', 'mail', 'aliyun', ' DingTalk',
    'suning', 'coupon', 'ctrip', 'qunar', 'fliggy', 'hotel',
    'didi', 'grab', 'gojek', 'line',
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

    # Skip very short second-level domains (e.g., "a.co" is suspicious)
    parts = domain.split('.')
    if len(parts) >= 2:
        sld = parts[-2]  # second-level domain
        if len(sld) < 2:
            return False

    # Skip TLDs that are too country-specific or problematic
    for tld in EXCLUDE_TLDS:
        if domain.endswith(tld):
            return False

    # Skip domains with China-based keywords
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
    regional = []
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


def test_domain_openssl(domain: str, timeout: float = 5.0) -> Tuple[str, bool]:
    """
    Test if domain supports TLS 1.3 with ALPN h2 using openssl.
    Returns (domain, True) if compatible, (domain, False) otherwise.
    """
    try:
        cmd = [
            'openssl', 's_client',
            '-connect', f'{domain}:443',
            '-alpn', 'h2',
            '-tls1_3',
            '-sess_out', '/dev/null',
            '-sess_id', '/dev/null',
            '-servername', domain,
        ]
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
    args = parser.parse_args()

    print("=" * 60)
    print("Reality SNI Domain Fetcher")
    print("=" * 60)
    print()

    # Step 1: Fetch domains from all sources
    print(f"[1/4] Fetching domain lists...")
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

    # Fetch from external domain list sources
    # v2fly/domain-list-community provides plain-text domain lists
    GEO_CATEGORIES = [
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/cloudflare',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/microsoft',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/google',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/apple',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/amazon',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/facebook',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/telegram',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/twitter',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/netflix',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/spotify',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/github',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/openai',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/speedtest',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/office',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/adobe',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/aws',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/digitalocean',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/linode',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/vultr',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/facebook',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/reddit',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/linkedin',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/discord',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/whatsapp',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/tiktok',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/youtube',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/twitch',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/steam',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/EpicGames',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/paypal',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/stripe',
        'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/shopify',
    ]
    print(f"  Fetching from {len(GEO_CATEGORIES)} external sources...")
    for url in GEO_CATEGORIES:
        fetched = fetch_domain_list(url)
        if fetched:
            all_domains.update(fetched)
            print(f"    {url.split('/')[-1]}: +{len(fetched)} domains")
        else:
            print(f"    {url.split('/')[-1]}: empty or failed")

    print(f"  Total unique domains after fetching: {len(all_domains)}")

    # Step 2: Filter and validate
    print(f"[2/5] Filtering domains...")
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
    print(f"[3/5] Testing domains with TLS 1.3 + ALPN h2...")
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

    # Step 4: Write output
    print(f"[4/5] Writing results...")
    compatible_domains.sort(key=lambda x: (len(x), x))

    with open(args.output, 'w') as f:
        for domain in compatible_domains:
            f.write(domain + '\n')

    print(f"  Compatible domains found: {len(compatible_domains)}")
    print(f"  Output written to: {args.output}")

    # Print summary
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  External sources checked: {len(GEO_CATEGORIES)}")
    print(f"  Domains collected: {len(all_domains)}")
    print(f"  Domains tested: {len(final_domains)}")
    print(f"  TLS 1.3 + ALPN h2 compatible: {len(compatible_domains)}")
    if compatible_domains:
        print(f"\n  Top 10 compatible domains:")
        for d in compatible_domains[:10]:
            print(f"    - {d}")


if __name__ == '__main__':
    main()
