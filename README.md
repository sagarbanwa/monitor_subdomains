#🔍 Monitor Subdomains - Automated Subdomain Discovery & Monitoring

Monitor Subdomains is a powerful Golang tool that continuously discovers and monitors subdomains for given domains. It leverages multiple security tools to identify new subdomains, analyze technologies, take screenshots, and send real-time notifications via Discord.

#🚀 Features

Continuous Monitoring: Scans for new subdomains every 20 minutes.

Multiple Enumeration Tools: Uses subfinder, amass, assetfinder, findomain, puredns, and dnsx for subdomain discovery.

Resolver Management: Downloads and updates the latest resolvers before each scan.

Technology Detection: Uses Wappalyzer-like tools to detect technologies running on discovered subdomains.

Screenshot Capture: Captures screenshots of newly found subdomains using gowitness.

Structured Data Storage: Saves subdomains, screenshots, and technology data in organized domain-specific folders.

Discord Notifications: Sends newly discovered subdomains, detected technologies, and screenshots to a Discord channel.

Supports Bulk Domains: Accepts a list of domains using -l <file>.

#📌 Installation

Ensure you have the required dependencies installed:
```
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v3/...@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/findomain/findomain@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/sensepost/gowitness@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```
#🔧 Usage

Monitor a single domain:

```./monitor_subdomains example.com```

Monitor multiple domains from a file:

```./monitor_subdomains -l domains.txt```

Example domains.txt:
```
example.com
target.com
anotherdomain.org
```

#📂 Output Structure

```
results/
  ├── example.com/
  │   ├── subdomains.txt
  │   ├── screenshots/
  │   ├── technologies.json
  ├── target.com/
  │   ├── subdomains.txt
  │   ├── screenshots/
  │   ├── technologies.json
```

#🛠 Upcoming Features

Integration with Security APIs: SecurityTrails, Shodan, and more.

Passive Reconnaissance: Fetching subdomains from multiple online sources.

CNAME & TLS Extraction: Using dnsx and cero for deeper analysis.

Automated Vulnerability Scanning: Running nuclei on discovered subdomains.

#🤝 Contributions

Pull requests and issues are welcome! Help improve and expand the tool.

