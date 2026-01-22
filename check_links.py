#!/usr/bin/env python3
"""
Link Checker Script for Portfolio Documentation
Finds all links in markdown files and validates them.
"""

import os
import re
import sys
import urllib.request
import urllib.error
import ssl
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Configuration
PORTFOLIO_ROOT = Path(__file__).parent
EXCLUDE_DIRS = {'.git', '.venv', 'node_modules', '__pycache__', '.cache'}
TIMEOUT = 10  # seconds for HTTP requests

# Regex patterns for links
MARKDOWN_LINK_PATTERN = re.compile(r'\[([^\]]*)\]\(([^)]+)\)')
BADGE_URL_PATTERN = re.compile(r'!\[([^\]]*)\]\(([^)]+)\)')
RAW_URL_PATTERN = re.compile(r'https?://[^\s\)>\]]+')


def find_markdown_files(root_dir: Path) -> list[Path]:
    """Find all markdown files in the repository."""
    md_files = []
    for path in root_dir.rglob('*.md'):
        # Skip excluded directories
        if any(excluded in path.parts for excluded in EXCLUDE_DIRS):
            continue
        md_files.append(path)
    return sorted(md_files)


def extract_links(file_path: Path) -> list[dict]:
    """Extract all links from a markdown file."""
    links = []
    try:
        content = file_path.read_text(encoding='utf-8')
    except Exception as e:
        print(f"  ⚠ Error reading {file_path}: {e}")
        return links

    lines = content.split('\n')

    for line_num, line in enumerate(lines, 1):
        # Find markdown links [text](url)
        for match in MARKDOWN_LINK_PATTERN.finditer(line):
            text, url = match.groups()
            # Skip image badges for now (they're external services)
            if url.startswith('https://img.shields.io'):
                continue
            links.append({
                'file': file_path,
                'line': line_num,
                'text': text,
                'url': url.strip(),
                'type': classify_link(url)
            })

        # Find raw URLs that aren't part of markdown links
        # Remove markdown links first to avoid duplicates
        line_without_md_links = MARKDOWN_LINK_PATTERN.sub('', line)
        line_without_badges = BADGE_URL_PATTERN.sub('', line_without_md_links)

        for match in RAW_URL_PATTERN.finditer(line_without_badges):
            url = match.group()
            # Clean trailing punctuation
            url = url.rstrip('.,;:')
            if url.startswith('https://img.shields.io'):
                continue
            links.append({
                'file': file_path,
                'line': line_num,
                'text': '[raw URL]',
                'url': url,
                'type': 'external'
            })

    return links


def classify_link(url: str) -> str:
    """Classify a link as internal, external, or anchor."""
    if url.startswith(('http://', 'https://')):
        return 'external'
    elif url.startswith('#'):
        return 'anchor'
    elif url.startswith('mailto:'):
        return 'email'
    else:
        return 'internal'


def check_internal_link(link: dict, root_dir: Path) -> dict:
    """Check if an internal link (file path) exists."""
    url = link['url']
    file_path = link['file']

    # Remove anchor from URL
    clean_url = url.split('#')[0] if '#' in url else url

    if not clean_url:
        # Pure anchor link, assume valid
        return {**link, 'status': 'ok', 'message': 'Anchor link'}

    # Resolve relative path
    if clean_url.startswith('/'):
        target_path = root_dir / clean_url.lstrip('/')
    else:
        target_path = file_path.parent / clean_url

    # Normalize the path
    try:
        target_path = target_path.resolve()
    except Exception:
        return {**link, 'status': 'error', 'message': 'Invalid path'}

    # Check if file or directory exists
    if target_path.exists():
        return {**link, 'status': 'ok', 'message': 'Exists'}
    elif target_path.with_suffix('.md').exists():
        return {**link, 'status': 'ok', 'message': 'Exists (with .md)'}
    elif (target_path / 'README.md').exists():
        return {**link, 'status': 'ok', 'message': 'Exists (directory with README)'}
    elif (target_path / 'index.md').exists():
        return {**link, 'status': 'ok', 'message': 'Exists (directory with index)'}
    else:
        return {**link, 'status': 'broken', 'message': f'Not found: {target_path}'}


def check_external_link(link: dict) -> dict:
    """Check if an external URL is accessible."""
    url = link['url']

    # Create SSL context that doesn't verify (for simplicity)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (Link Checker)'}
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as response:
            status_code = response.getcode()
            if status_code == 200:
                return {**link, 'status': 'ok', 'message': f'HTTP {status_code}'}
            else:
                return {**link, 'status': 'warning', 'message': f'HTTP {status_code}'}
    except urllib.error.HTTPError as e:
        if e.code == 403:
            return {**link, 'status': 'warning', 'message': f'HTTP 403 (Forbidden - may require auth)'}
        elif e.code == 404:
            return {**link, 'status': 'broken', 'message': 'HTTP 404 Not Found'}
        else:
            return {**link, 'status': 'error', 'message': f'HTTP {e.code}'}
    except urllib.error.URLError as e:
        return {**link, 'status': 'error', 'message': f'URL Error: {e.reason}'}
    except Exception as e:
        return {**link, 'status': 'error', 'message': str(e)[:50]}


def check_link(link: dict, root_dir: Path) -> dict:
    """Check a single link based on its type."""
    link_type = link['type']

    if link_type == 'internal':
        return check_internal_link(link, root_dir)
    elif link_type == 'external':
        return check_external_link(link)
    elif link_type == 'email':
        return {**link, 'status': 'skipped', 'message': 'Email link'}
    elif link_type == 'anchor':
        return {**link, 'status': 'skipped', 'message': 'Anchor link'}
    else:
        return {**link, 'status': 'unknown', 'message': 'Unknown type'}


def print_results(results: list[dict], show_all: bool = False):
    """Print the results in a formatted way."""
    # Group by status
    by_status = defaultdict(list)
    for r in results:
        by_status[r['status']].append(r)

    # Summary
    print("\n" + "=" * 70)
    print("LINK CHECK SUMMARY")
    print("=" * 70)
    print(f"  ✅ OK:      {len(by_status['ok'])}")
    print(f"  ⚠️  Warning: {len(by_status['warning'])}")
    print(f"  ❌ Broken:  {len(by_status['broken'])}")
    print(f"  ⏭️  Skipped: {len(by_status['skipped'])}")
    print(f"  🔴 Error:   {len(by_status['error'])}")
    print(f"  📊 Total:   {len(results)}")

    # Show broken links
    if by_status['broken']:
        print("\n" + "-" * 70)
        print("BROKEN LINKS")
        print("-" * 70)
        for r in by_status['broken']:
            rel_path = r['file'].relative_to(PORTFOLIO_ROOT)
            print(f"\n  📁 {rel_path}:{r['line']}")
            print(f"     Link: [{r['text'][:40]}...]" if len(r['text']) > 40 else f"     Link: [{r['text']}]")
            print(f"     URL:  {r['url']}")
            print(f"     Error: {r['message']}")

    # Show warnings
    if by_status['warning']:
        print("\n" + "-" * 70)
        print("WARNINGS")
        print("-" * 70)
        for r in by_status['warning']:
            rel_path = r['file'].relative_to(PORTFOLIO_ROOT)
            print(f"\n  📁 {rel_path}:{r['line']}")
            print(f"     URL: {r['url']}")
            print(f"     Warning: {r['message']}")

    # Show errors
    if by_status['error']:
        print("\n" + "-" * 70)
        print("ERRORS")
        print("-" * 70)
        for r in by_status['error']:
            rel_path = r['file'].relative_to(PORTFOLIO_ROOT)
            print(f"\n  📁 {rel_path}:{r['line']}")
            print(f"     URL: {r['url']}")
            print(f"     Error: {r['message']}")

    # Show all links if requested
    if show_all:
        print("\n" + "-" * 70)
        print("ALL LINKS")
        print("-" * 70)
        for r in results:
            rel_path = r['file'].relative_to(PORTFOLIO_ROOT)
            status_icon = {'ok': '✅', 'warning': '⚠️', 'broken': '❌', 'skipped': '⏭️', 'error': '🔴'}.get(r['status'], '❓')
            print(f"  {status_icon} [{r['type']:8}] {rel_path}:{r['line']} -> {r['url'][:60]}")


def main():
    """Main entry point."""
    print("=" * 70)
    print("PORTFOLIO LINK CHECKER")
    print("=" * 70)

    show_all = '--all' in sys.argv
    check_external = '--no-external' not in sys.argv

    # Find all markdown files
    print(f"\n📂 Scanning: {PORTFOLIO_ROOT}")
    md_files = find_markdown_files(PORTFOLIO_ROOT)
    print(f"   Found {len(md_files)} markdown files (excluding .venv, .git, etc.)")

    # Extract all links
    print("\n🔍 Extracting links...")
    all_links = []
    for md_file in md_files:
        links = extract_links(md_file)
        all_links.extend(links)

    print(f"   Found {len(all_links)} links total")

    # Count by type
    by_type = defaultdict(int)
    for link in all_links:
        by_type[link['type']] += 1

    print(f"   - Internal: {by_type['internal']}")
    print(f"   - External: {by_type['external']}")
    print(f"   - Anchor:   {by_type['anchor']}")
    print(f"   - Email:    {by_type['email']}")

    # Check links
    print("\n🔗 Checking links...")
    results = []

    # Check internal links (fast, do first)
    internal_links = [l for l in all_links if l['type'] == 'internal']
    for link in internal_links:
        result = check_link(link, PORTFOLIO_ROOT)
        results.append(result)

    # Check external links with threading (slower)
    if check_external:
        external_links = [l for l in all_links if l['type'] == 'external']
        print(f"   Checking {len(external_links)} external links (this may take a moment)...")

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_link, link, PORTFOLIO_ROOT): link for link in external_links}
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                # Progress indicator
                checked = len([r for r in results if r['type'] == 'external'])
                print(f"\r   Progress: {checked}/{len(external_links)}", end='', flush=True)
        print()  # New line after progress

    # Add skipped links
    for link in all_links:
        if link['type'] in ('anchor', 'email'):
            results.append({**link, 'status': 'skipped', 'message': f'{link["type"]} link'})

    # Print results
    print_results(results, show_all)

    # Exit with error code if broken links found
    broken_count = len([r for r in results if r['status'] == 'broken'])
    if broken_count > 0:
        print(f"\n❌ Found {broken_count} broken link(s)!")
        sys.exit(1)
    else:
        print("\n✅ All links are valid!")
        sys.exit(0)


if __name__ == '__main__':
    main()
