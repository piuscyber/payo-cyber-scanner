import requests, ssl, socket, os, base64
from urllib.parse import urlparse
from datetime import datetime
from colorama import Fore, Style, init
from dotenv import load_dotenv

load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
init(autoreset=True)

def get_virustotal_score(url):
    if not VIRUSTOTAL_API_KEY:
        return None
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json()['data']['attributes']['last_analysis_stats']
        return None
    except:
        return None

def check_single(url):
    if not url.startswith("http"):
        url = "https://" + url
    domain = urlparse(url).netloc or url.split('/')[0]
    result = {"url": url, "secure": False, "ssl_days": 0, "status": 0, "virustotal": None}
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        final = r.url
        if final.startswith("https://"):
            print(f"{Fore.GREEN}[✓] SECURE: {final}")
            result["secure"] = True
        else:
            print(f"{Fore.RED}[!] INSECURE: {final}")
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(4)
                s.connect((domain, 443))
                cert = s.getpeercert()
                expire = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                result["ssl_days"] = (expire - datetime.now()).days
                print(f"{Fore.CYAN}SSL: {result['ssl_days']} days left")
        except:
            pass
        result["status"] = r.status_code
        vt = get_virustotal_score(url)
        if vt:
            result["virustotal"] = vt
            print(f"{Fore.YELLOW}VirusTotal: {vt.get('malicious', 0)} malicious")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}")
    return result

def bulk_scan():
    results = []
    try:
        with open("urls.txt", "r") as f:
            urls = [line.strip() for line in f if line.strip()]
        print(f"\nScanning {len(urls)} URLs...\n")
        for u in urls:
            results.append(check_single(u))
    except FileNotFoundError:
        url = input("Enter URL (e.g. google.com): ").strip()
        results = [check_single(url)]

    # Save report
    with open("security_report.txt", "w") as out:
        out.write(f"Scan Report - {datetime.now()}\n")
        out.write("-"*50 + "\n")
        for r in results:
            status = "SECURE" if r["secure"] else "INSECURE"
            out.write(f"{r['url']} -> {status} | SSL: {r['ssl_days']} days | Status: {r['status']}\n")
            if r.get("virustotal"):
                out.write(f"  VirusTotal: {r['virustotal']}\n")

    print(f"\n{Fore.CYAN}[*] Report saved to security_report.txt")
    secure_count = sum(1 for r in results if r["secure"])
    print(f"Summary: {secure_count}/{len(results)} secure")

if __name__ == "__main__":
    bulk_scan()