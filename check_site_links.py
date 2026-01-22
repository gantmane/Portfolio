#!/usr/bin/env python3
"""
GitHub Pages Site Link Checker
Crawls the live site and checks all links for 404 errors.
"""

import re
import sys
import urllib.request
import urllib.error
import ssl
from urllib.parse import urljoin, urlparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
BASE_URL = "https://gantmane.github.io/Portfolio/"
TIMEOUT = 15
MAX_PAGES = 200
USER_AGENT = "Mozilla/5.0 (Site Link Checker)"

# SSL context
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# Track visited URLs
visited = set()
results = []


def fetch_page(url: str) -> tuple[int, str]:
    """Fetch a page and return status code and content."""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as response:
            content = response.read().decode('utf-8', errors='ignore')
            return response.getcode(), content
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return 0, str(e)


def extract_links(html: str, base_url: str) -> list[str]:
    """Extract all href links from HTML."""
    links = []
    # Find all href attributes
    pattern = r'href=["\']([^"\']+)["\']'
    for match in re.finditer(pattern, html):
        href = match.group(1)
        # Skip anchors, javascript, mailto
        if href.startswith(('#', 'javascript:', 'mailto:')):
            continue
        # Convert relative to absolute
        full_url = urljoin(base_url, href)
        links.append(full_url)
    return links


def is_internal(url: str) -> bool:
    """Check if URL is internal to the site."""
    return url.startswith(BASE_URL)


def check_link(url: str) -> dict:
    """Check a single link and return result."""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT}, method='HEAD')
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as response:
            return {'url': url, 'status': response.getcode(), 'error': None}
    except urllib.error.HTTPError as e:
        return {'url': url, 'status': e.code, 'error': None}
    except Exception as e:
        return {'url': url, 'status': 0, 'error': str(e)[:50]}


def crawl_site():
    """Crawl the site starting from base URL."""
    to_visit = [BASE_URL]
    all_links = []  # (source_page, target_url)

    print(f"🌐 Starting crawl from: {BASE_URL}")
    print("-" * 60)

    while to_visit and len(visited) < MAX_PAGES:
        url = to_visit.pop(0)

        if url in visited:
            continue

        visited.add(url)
        status, content = fetch_page(url)

        if status == 200:
            print(f"  ✓ {url}")
            links = extract_links(content, url)

            for link in links:
                all_links.append((url, link))
                # Add internal links to crawl queue
                if is_internal(link) and link not in visited and link not in to_visit:
                    # Only crawl HTML pages, not files
                    if not any(link.endswith(ext) for ext in ['.pdf', '.png', '.jpg', '.xml', '.yaml', '.tf', '.py', '.sh']):
                        to_visit.append(link)
        else:
            print(f"  ✗ {url} (HTTP {status})")

    return all_links


def check_all_links(all_links: list[tuple[str, str]]):
    """Check all collected links."""
    # Deduplicate links
    unique_links = {}
    for source, target in all_links:
        if target not in unique_links:
            unique_links[target] = []
        unique_links[target].append(source)

    print(f"\n🔗 Checking {len(unique_links)} unique links...")
    print("-" * 60)

    results = []

    # Check links in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_link, url): url for url in unique_links.keys()}
        done = 0
        for future in as_completed(futures):
            result = future.result()
            result['sources'] = unique_links[result['url']]
            results.append(result)
            done += 1
            print(f"\r  Progress: {done}/{len(unique_links)}", end='', flush=True)

    print()
    return results


def print_report(results: list[dict]):
    """Print the final report."""
    # Categorize results
    ok = [r for r in results if r['status'] == 200]
    redirects = [r for r in results if 300 <= r['status'] < 400]
    not_found = [r for r in results if r['status'] == 404]
    other_errors = [r for r in results if r['status'] not in [200, 404] and 300 > r['status'] or r['status'] >= 400]
    errors = [r for r in results if r['status'] == 0]

    # Filter for internal 404s (the bug we're looking for)
    internal_404s = [r for r in not_found if r['url'].startswith(BASE_URL)]
    external_404s = [r for r in not_found if not r['url'].startswith(BASE_URL)]

    print("\n" + "=" * 60)
    print("SITE LINK CHECK REPORT")
    print("=" * 60)
    print(f"  ✅ OK (200):        {len(ok)}")
    print(f"  ↪️  Redirects:       {len(redirects)}")
    print(f"  ❌ Internal 404:    {len(internal_404s)}")
    print(f"  ⚠️  External 404:    {len(external_404s)}")
    print(f"  🔴 Other errors:    {len(other_errors) + len(errors)}")
    print(f"  📊 Total checked:   {len(results)}")

    # Show internal 404s (the main bug)
    if internal_404s:
        print("\n" + "-" * 60)
        print("❌ INTERNAL BROKEN LINKS (404)")
        print("-" * 60)
        for r in internal_404s:
            print(f"\n  URL: {r['url']}")
            print(f"  Found on:")
            for source in r['sources'][:3]:  # Show up to 3 sources
                print(f"    - {source}")
            if len(r['sources']) > 3:
                print(f"    ... and {len(r['sources']) - 3} more pages")

    # Show external 404s
    if external_404s:
        print("\n" + "-" * 60)
        print("⚠️  EXTERNAL BROKEN LINKS (404)")
        print("-" * 60)
        for r in external_404s[:10]:  # Limit to 10
            print(f"\n  URL: {r['url']}")
            print(f"  Found on: {r['sources'][0]}")
        if len(external_404s) > 10:
            print(f"\n  ... and {len(external_404s) - 10} more external 404s")

    # Show other errors
    if other_errors or errors:
        print("\n" + "-" * 60)
        print("🔴 OTHER ERRORS")
        print("-" * 60)
        for r in (other_errors + errors)[:10]:
            print(f"\n  URL: {r['url']}")
            print(f"  Status: {r['status']} {r.get('error', '')}")

    return len(internal_404s)


def main():
    print("=" * 60)
    print("GITHUB PAGES SITE LINK CHECKER")
    print("=" * 60)
    print(f"Base URL: {BASE_URL}")
    print()

    # Step 1: Crawl the site
    print("📖 Phase 1: Crawling site pages...")
    all_links = crawl_site()
    print(f"\n  Crawled {len(visited)} pages, found {len(all_links)} links")

    # Step 2: Check all links
    print("\n📡 Phase 2: Checking all links...")
    results = check_all_links(all_links)

    # Step 3: Print report
    broken_count = print_report(results)

    # Exit code
    if broken_count > 0:
        print(f"\n❌ Found {broken_count} internal broken links!")
        sys.exit(1)
    else:
        print("\n✅ No internal broken links found!")
        sys.exit(0)


if __name__ == '__main__':
    main()
