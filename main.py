from urllib.parse import urlparse
import ipaddress
import re

def check_url(url):
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""
    reasons = []

    if not host:
        return "Invalid URL"

    if parsed.scheme != "https":
        reasons.append("Not using HTTPS")

    try:
        ipaddress.ip_address(host)
        reasons.append("Uses an IP address instead of a domain")
    except ValueError:
        pass

    if "@" in url:
        reasons.append("Contains @ symbol")

    if len(url) > 100:
        reasons.append("Unusually long URL")

    if host.count(".") >= 4:
        reasons.append("Contains many subdomains")

    suspicious_words = [
        "login", "verify", "password",
        "update", "account", "secure"
    ]

    if any(word in url.lower() for word in suspicious_words):
        reasons.append("Contains potentially suspicious keywords")

    if reasons:
        print("\n⚠️ Potentially Suspicious URL")
        for reason in reasons:
            print("-", reason)
        print("\nNote: These indicators do not prove a URL is malicious.")
    else:
        print("\nNo obvious warning signs detected.")
        print("This does NOT guarantee that the URL is safe.")

url = input("Enter a URL to check: ")
check_url(url)
