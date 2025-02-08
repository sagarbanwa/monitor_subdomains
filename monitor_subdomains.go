package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

var (
	checkInterval    = 20 * time.Minute
	resolversURL     = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
	wordlistURL      = "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt"
	permutationsURL  = "https://gist.githubusercontent.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw"
	resolversFile    = "/usr/share/resolvers.txt"
	wordlistFile     = "/usr/share/best-dns-wordlist.txt"
	permutationsFile = "/usr/share/dns_permutations_list.txt"
	subdomainsDir    = "subdomains"
	outputDir        = "results"
	discordWebhook   = "YOUR_DISCORD_WEBHOOK_URL"
)

func downloadFile(url, filepath string) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("[!] Failed to download:", url, err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("[!] Failed to read response:", url, err)
		return
	}

	err = ioutil.WriteFile(filepath, body, 0644)
	if err != nil {
		fmt.Println("[!] Failed to save file:", filepath, err)
	}
}

func runCommand(cmd string) []string {
	var out bytes.Buffer
	command := exec.Command("sh", "-c", cmd)
	command.Stdout = &out
	_ = command.Run()
	return strings.Split(strings.TrimSpace(out.String()), "\n")
}

func findSubdomains(domain string) []string {
	cmds := []string{
		"subfinder -d " + domain + " -rL " + resolversFile,
		"amass enum -passive -d " + domain + " -rf " + resolversFile,
		"assetfinder --subs-only " + domain,
		"findomain --target " + domain + " --resolvers " + resolversFile + " --threads 40 -u temp.txt && cat temp.txt",
		"puredns bruteforce " + wordlistFile + " " + domain + " -r " + resolversFile,
		"dnsx -retry 3 -cname -l temp.txt",
	}
	var subdomains []string
	for _, cmd := range cmds {
		subdomains = append(subdomains, runCommand(cmd)...)
	}
	return subdomains
}

func analyzeTechnologies(domain string) string {
	techOutput := runCommand("wappalyzer-cli " + domain)
	return strings.Join(techOutput, ", ")
}

func takeScreenshot(domain string) {
	exec.Command("gowitness", "single", "-u", "http://"+domain, "-d", outputDir).Run()
}

func sendNotification(domain string, newSubs []string, techInfo map[string]string) {
	if len(newSubs) == 0 {
		return
	}
	message := fmt.Sprintf("New subdomains found for %s:\n", domain)
	for _, sub := range newSubs {
		message += fmt.Sprintf("%s - Technologies: %s\n", sub, techInfo[sub])
	}

	payload := fmt.Sprintf("{\"content\": \"%s\"}", message)
	exec.Command("curl", "-X", "POST", "-H", "Content-Type: application/json", "-d", payload, discordWebhook).Run()
}

func saveSubdomains(domain string, subdomains []string) {
	domainDir := fmt.Sprintf("%s/%s", outputDir, domain)
	if _, err := os.Stat(domainDir); os.IsNotExist(err) {
		os.MkdirAll(domainDir, 0755)
	}
	filepath := fmt.Sprintf("%s/subdomains.txt", domainDir)
	existingSubs := runCommand("cat " + filepath)

	var newSubs []string
	techInfo := make(map[string]string)
	subMap := make(map[string]bool)
	for _, sub := range existingSubs {
		subMap[sub] = true
	}
	for _, sub := range subdomains {
		if !subMap[sub] {
			newSubs = append(newSubs, sub)
			techInfo[sub] = analyzeTechnologies(sub)
			takeScreenshot(sub)
		}
	}

	file, _ := os.Create(filepath)
	defer file.Close()
	for _, sub := range subdomains {
		file.WriteString(sub + "\n")
	}

	sendNotification(domain, newSubs, techInfo)
}

func monitorSubdomains(domains []string) {
	for {
		fmt.Println("[+] Downloading latest resolvers, wordlist, and permutations list...")
		downloadFile(resolversURL, resolversFile)
		downloadFile(wordlistURL, wordlistFile)
		downloadFile(permutationsURL, permutationsFile)

		for _, domain := range domains {
			fmt.Println("[+] Scanning for subdomains of", domain)
			foundSubs := findSubdomains(domain)
			saveSubdomains(domain, foundSubs)
			fmt.Println("[+] Found and saved subdomains for", domain)
		}

		fmt.Printf("[*] Sleeping for %v...\n", checkInterval)
		time.Sleep(checkInterval)
	}
}

func main() {
	listFile := flag.String("l", "", "File containing list of domains")
	flag.Parse()

	var domains []string
	if *listFile != "" {
		file, err := os.Open(*listFile)
		if err != nil {
			fmt.Println("[!] Failed to open domain list file:", err)
			os.Exit(1)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			domains = append(domains, scanner.Text())
		}
	} else if len(flag.Args()) > 0 {
		domains = flag.Args()
	} else {
		fmt.Println("Usage: ./monitor_subdomains -l <domain_list> OR ./monitor_subdomains <domain1> <domain2> ...")
		os.Exit(1)
	}

	monitorSubdomains(domains)
}
