#!/usr/bin/env python3
"""Domain lookup CLI tool with parallel execution."""

import sys
import socket
import ssl
import subprocess
import concurrent.futures
from datetime import datetime

import dns.resolver
import whois
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich import box

console = Console()


def get_dns_records(domain: str) -> dict:
    """Fetch various DNS records."""
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            records[rtype] = []
    
    return {"dns_records": records}


def get_whois_info(domain: str) -> dict:
    """Fetch WHOIS information."""
    try:
        w = whois.whois(domain)
        return {
            "whois": {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "name_servers": w.name_servers if w.name_servers else [],
                "status": w.status if w.status else [],
                "org": w.org,
                "country": w.country,
            }
        }
    except Exception as e:
        return {"whois": {"error": str(e)}}


def get_ip_info(domain: str) -> dict:
    """Get IP address and geolocation."""
    try:
        ip = socket.gethostbyname(domain)
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = resp.json()
        return {
            "ip_info": {
                "ip": ip,
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
            }
        }
    except Exception as e:
        return {"ip_info": {"error": str(e)}}


def get_ssl_info(domain: str) -> dict:
    """Get SSL certificate information."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
        
        return {
            "ssl": {
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "valid_from": cert.get("notBefore"),
                "valid_until": cert.get("notAfter"),
                "serial": cert.get("serialNumber"),
            }
        }
    except Exception as e:
        return {"ssl": {"error": str(e)}}


def get_http_headers(domain: str) -> dict:
    """Get HTTP response headers."""
    try:
        resp = requests.head(f"https://{domain}", timeout=5, allow_redirects=True)
        headers = dict(resp.headers)
        return {
            "http": {
                "status_code": resp.status_code,
                "server": headers.get("Server"),
                "x_powered_by": headers.get("X-Powered-By"),
                "content_type": headers.get("Content-Type"),
                "strict_transport": headers.get("Strict-Transport-Security"),
                "x_frame_options": headers.get("X-Frame-Options"),
                "x_xss_protection": headers.get("X-XSS-Protection"),
                "final_url": resp.url,
            }
        }
    except Exception as e:
        return {"http": {"error": str(e)}}


def get_subdomains(domain: str) -> dict:
    """Run subfinder to discover subdomains."""
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=60,
            env={**subprocess.os.environ, "PATH": subprocess.os.environ.get("PATH", "") + ":/home/linuxbrew/.linuxbrew/bin"}
        )
        subs = [s.strip() for s in result.stdout.strip().split('\n') if s.strip()]
        if result.returncode != 0 and result.stderr:
            return {"subdomains": [], "subdomains_error": result.stderr}
        return {"subdomains": subs[:20]}
    except subprocess.TimeoutExpired:
        return {"subdomains": [], "subdomains_error": "Timeout (60s)"}
    except FileNotFoundError:
        return {"subdomains": [], "subdomains_error": "subfinder not found"}
    except Exception as e:
        return {"subdomains": [], "subdomains_error": str(e)}


def get_reverse_dns(domain: str) -> dict:
    """Get reverse DNS."""
    try:
        ip = socket.gethostbyname(domain)
        hostname = socket.gethostbyaddr(ip)
        return {"reverse_dns": {"ip": ip, "hostname": hostname[0], "aliases": hostname[1]}}
    except Exception as e:
        return {"reverse_dns": {"error": str(e)}}


def get_security_headers(domain: str) -> dict:
    """Check security headers."""
    try:
        resp = requests.get(f"https://{domain}", timeout=5)
        h = resp.headers
        checks = {
            "HSTS": "Strict-Transport-Security" in h,
            "X-Frame-Options": "X-Frame-Options" in h,
            "X-Content-Type-Options": "X-Content-Type-Options" in h,
            "X-XSS-Protection": "X-XSS-Protection" in h,
            "Content-Security-Policy": "Content-Security-Policy" in h,
            "Referrer-Policy": "Referrer-Policy" in h,
            "Permissions-Policy": "Permissions-Policy" in h,
        }
        return {"security_headers": checks}
    except Exception as e:
        return {"security_headers": {"error": str(e)}}


def display_results(domain: str, results: dict):
    """Display results in a nice format."""
    console.print()
    console.print(Panel(f"[bold cyan]Domain Report: {domain}[/]", box=box.DOUBLE))
    
    # IP & Location
    ip_info = results.get("ip_info", {})
    if "error" not in ip_info:
        table = Table(title="🌐 IP & Location", box=box.ROUNDED, show_header=False)
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="white")
        for k, v in ip_info.items():
            if v:
                table.add_row(k.upper(), str(v))
        console.print(table)
    
    # WHOIS
    whois_info = results.get("whois", {})
    if "error" not in whois_info:
        table = Table(title="📋 WHOIS Information", box=box.ROUNDED, show_header=False)
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="white")
        for k, v in whois_info.items():
            if v:
                val = ", ".join(v) if isinstance(v, list) else str(v)
                table.add_row(k.replace("_", " ").title(), val[:80])
        console.print(table)
    
    # SSL
    ssl_info = results.get("ssl", {})
    if "error" not in ssl_info:
        table = Table(title="🔒 SSL Certificate", box=box.ROUNDED, show_header=False)
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="white")
        if ssl_info.get("issuer"):
            table.add_row("Issuer", ssl_info["issuer"].get("organizationName", "N/A"))
        if ssl_info.get("subject"):
            table.add_row("Subject", ssl_info["subject"].get("commonName", "N/A"))
        table.add_row("Valid From", str(ssl_info.get("valid_from", "N/A")))
        table.add_row("Valid Until", str(ssl_info.get("valid_until", "N/A")))
        console.print(table)
    
    # HTTP
    http_info = results.get("http", {})
    if "error" not in http_info:
        table = Table(title="🌍 HTTP Info", box=box.ROUNDED, show_header=False)
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="white")
        for k, v in http_info.items():
            if v:
                table.add_row(k.replace("_", " ").title(), str(v)[:60])
        console.print(table)
    
    # Security Headers
    sec_headers = results.get("security_headers", {})
    if "error" not in sec_headers:
        table = Table(title="🛡️ Security Headers", box=box.ROUNDED, show_header=False)
        table.add_column("Header", style="cyan")
        table.add_column("Status", style="white")
        for k, v in sec_headers.items():
            status = "[green]✓ Present[/]" if v else "[red]✗ Missing[/]"
            table.add_row(k, status)
        console.print(table)
    
    # DNS Records
    dns_records = results.get("dns_records", {})
    table = Table(title="📡 DNS Records", box=box.ROUNDED)
    table.add_column("Type", style="cyan")
    table.add_column("Records", style="white")
    for rtype, records in dns_records.items():
        if records:
            table.add_row(rtype, "\n".join(records[:5]))
    console.print(table)
    
    # Mail Server Detection
    mx_records = dns_records.get("MX", [])
    if mx_records:
        console.print(Panel("[green]✓ Mail server detected[/]", title="📧 Email"))
    else:
        console.print(Panel("[yellow]✗ No mail server detected[/]", title="📧 Email"))
    
    # Subdomains
    subdomains = results.get("subdomains", [])
    subdomains_error = results.get("subdomains_error")
    if isinstance(subdomains, list) and subdomains:
        table = Table(title=f"🔍 Subdomains ({len(subdomains)} found)", box=box.ROUNDED)
        table.add_column("Subdomain", style="cyan")
        for sub in subdomains[:15]:
            table.add_row(sub)
        if len(subdomains) > 15:
            table.add_row(f"... and {len(subdomains) - 15} more")
        console.print(table)
    elif subdomains_error:
        console.print(Panel(f"[red]Error: {subdomains_error}[/]", title="🔍 Subdomains"))
    else:
        console.print(Panel("[yellow]No subdomains found[/]", title="🔍 Subdomains"))
    
    # Reverse DNS
    rdns = results.get("reverse_dns", {})
    if "error" not in rdns:
        console.print(Panel(f"[cyan]{rdns.get('hostname', 'N/A')}[/]", title="🔄 Reverse DNS"))
    
    console.print()


def main():
    if len(sys.argv) < 2:
        console.print("[red]Usage: domaincheck <domain>[/]")
        sys.exit(1)
    
    domain = sys.argv[1].strip().lower()
    if domain.startswith("http"):
        domain = domain.split("//")[1].split("/")[0]
    
    console.print(f"\n[bold]Scanning {domain}...[/]\n")
    
    tasks = [
        get_dns_records,
        get_whois_info,
        get_ip_info,
        get_ssl_info,
        get_http_headers,
        get_subdomains,
        get_reverse_dns,
        get_security_headers,
    ]
    
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(task, domain): task.__name__ for task in tasks}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                results.update(result)
            except Exception as e:
                console.print(f"[red]Error in {futures[future]}: {e}[/]")
    
    display_results(domain, results)


if __name__ == "__main__":
    main()
