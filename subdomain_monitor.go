package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

const (
	checkInterval    = 20 * time.Minute
	resolversURL     = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
	wordlistURL      = "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt"
	permutationsURL  = "https://gist.githubusercontent.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw"
	
	// 🚨 IMPORTANT: REPLACE THIS WITH YOUR ACTUAL DISCORD WEBHOOK
	DEFAULT_DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1234567890/abcdefghijklmnopqrstuvwxyz"
)

// DiscordNotificationConfig allows customization of Discord notifications
type DiscordNotificationConfig struct {
	WebhookURL        string
	NotifyOnNewSubs   bool
	NotifyOnError     bool
	NotifyMinSubCount int
	CustomMessage     string
	Username          string
	AvatarURL         string
	Color             int
}

type SubdomainMonitor struct {
	domainsToMonitor []string
	outputDir        string
	resolversFile    string
	wordlistFile     string
	permutationsFile string
	discordConfig    *DiscordNotificationConfig
	logger           *log.Logger
}

// Enhanced Discord Embed structure for richer notifications
type DiscordEmbed struct {
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Color       int             `json:"color"`
	Fields      []DiscordField  `json:"fields,omitempty"`
	Footer      *DiscordFooter  `json:"footer,omitempty"`
	Timestamp   string          `json:"timestamp"`
}

type DiscordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type DiscordFooter struct {
	Text    string `json:"text"`
	IconURL string `json:"icon_url,omitempty"`
}

type DiscordPayload struct {
	Content     string         `json:"content,omitempty"`
	Username    string         `json:"username,omitempty"`
	AvatarURL   string         `json:"avatar_url,omitempty"`
	Embeds      []DiscordEmbed `json:"embeds,omitempty"`
}

// getDiscordWebhook provides a secure way to get the webhook
func getDiscordWebhook() string {
	// Priority 1: Environment Variable
	envWebhook := os.Getenv("DISCORD_WEBHOOK_URL")
	if envWebhook != "" {
		return envWebhook
	}

	// Priority 2: Hardcoded Webhook (with warning)
	if DEFAULT_DISCORD_WEBHOOK != "https://discord.com/api/webhooks/1234567890/abcdefghijklmnopqrstuvwxyz" {
		log.Println("⚠️ Warning: Using hardcoded webhook. Consider using environment variables for security.")
		return DEFAULT_DISCORD_WEBHOOK
	}

	// No webhook available
	log.Println("❌ No Discord webhook configured. Notifications will be disabled.")
	return ""
}

func NewDiscordNotificationConfig() *DiscordNotificationConfig {
	return &DiscordNotificationConfig{
		WebhookURL:        getDiscordWebhook(),
		NotifyOnNewSubs:   true,
		NotifyOnError:     true,
		NotifyMinSubCount: 1,
		CustomMessage:     "",
		Username:          "Subdomain Monitor",
		AvatarURL:         "https://icon.horse/icon/subdomain.monitor",
		Color:             0x3498db, // Soft blue color
	}
}

func NewSubdomainMonitor(domains []string, outputDir string, discordConfig *DiscordNotificationConfig) *SubdomainMonitor {
	return &SubdomainMonitor{
		domainsToMonitor: domains,
		outputDir:        outputDir,
		resolversFile:    filepath.Join(outputDir, "resolvers.txt"),
		wordlistFile:     filepath.Join(outputDir, "best-dns-wordlist.txt"),
		permutationsFile: filepath.Join(outputDir, "dns_permutations_list.txt"),
		discordConfig:    discordConfig,
		logger:           log.New(os.Stdout, "[SubdomainMonitor] ", log.LstdFlags),
	}
}

func (dc *DiscordNotificationConfig) sendRichDiscordNotification(title string, description string, fields []DiscordField, isError bool) error {
	if dc.WebhookURL == "" {
		return errors.New("no Discord webhook URL configured")
	}

	// Determine color based on error status
	color := dc.Color
	if isError {
		color = 0xff0000 // Red for errors
	}

	embed := DiscordEmbed{
		Title:       title,
		Description: description,
		Color:       color,
		Fields:      fields,
		Footer: &DiscordFooter{
			Text: "Subdomain Monitor",
			IconURL: "https://icon.horse/icon/subdomain.monitor",
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	payload := DiscordPayload{
		Username:  dc.Username,
		AvatarURL: dc.AvatarURL,
		Embeds:    []DiscordEmbed{embed},
	}

	// Add custom message if provided
	if dc.CustomMessage != "" {
		payload.Content = dc.CustomMessage
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(dc.WebhookURL, "application/json", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("discord webhook error: %s", string(body))
	}

	return nil
}

func (m *SubdomainMonitor) downloadFile(url, filepath string) error {
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	m.logger.Printf("Downloading %s", green(url))
	resp, err := http.Get(url)
	if err != nil {
		m.logger.Printf("%s Failed to download: %v", red("[ERROR]"), err)
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		m.logger.Printf("%s Failed to create file: %v", red("[ERROR]"), err)
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		m.logger.Printf("%s Failed to save file: %v", red("[ERROR]"), err)
		return err
	}

	return nil
}

func (m *SubdomainMonitor) runCommand(cmd string) ([]string, error) {
	command := exec.Command("sh", "-c", cmd)
	var out bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &out
	command.Stderr = &stderr

	err := command.Run()
	if err != nil {
		return nil, fmt.Errorf("command failed: %v - %s", err, stderr.String())
	}

	return strings.Split(strings.TrimSpace(out.String()), "\n"), nil
}

func (m *SubdomainMonitor) findSubdomains(domain string) ([]string, error) {
	cmds := []string{
		fmt.Sprintf("subfinder -d %s -rL %s", domain, m.resolversFile),
		fmt.Sprintf("amass enum -passive -d %s -rf %s", domain, m.resolversFile),
		fmt.Sprintf("assetfinder --subs-only %s", domain),
		fmt.Sprintf("findomain --target %s --resolvers %s --threads 40 -u temp.txt && cat temp.txt", domain, m.resolversFile),
		fmt.Sprintf("puredns bruteforce %s %s -r %s", m.wordlistFile, domain, m.resolversFile),
		"dnsx -retry 3 -cname -l temp.txt",
	}

	var allSubdomains []string
	for _, cmd := range cmds {
		subs, err := m.runCommand(cmd)
		if err != nil {
			m.logger.Printf("Error running command %s: %v", cmd, err)
			continue
		}
		allSubdomains = append(allSubdomains, subs...)
	}

	// Remove duplicates
	uniqueSubs := removeDuplicates(allSubdomains)
	return uniqueSubs, nil
}

func removeDuplicates(subs []string) []string {
	unique := make(map[string]bool)
	var result []string
	for _, sub := range subs {
		if !unique[sub] && sub != "" {
			unique[sub] = true
			result = append(result, sub)
		}
	}
	return result
}

func (m *SubdomainMonitor) analyzeTechnologies(domain string) (string, error) {
	output, err := m.runCommand(fmt.Sprintf("wappalyzer-cli %s", domain))
	if err != nil {
		return "", err
	}
	return strings.Join(output, ", "), nil
}

func (m *SubdomainMonitor) takeScreenshot(domain string) error {
	cmd := fmt.Sprintf("gowitness single -u http://%s -d %s", domain, m.outputDir)
	_, err := m.runCommand(cmd)
	return err
}

func (m *SubdomainMonitor) notifyNewSubdomains(domain string, newSubs []string, techInfo map[string]string) error {
	if len(newSubs) < m.discordConfig.NotifyMinSubCount {
		return nil
	}

	var fields []DiscordField
	for _, sub := range newSubs {
		tech := techInfo[sub]
		if tech == "" {
			tech = "No technology information"
		}
		fields = append(fields, DiscordField{
			Name:   sub,
			Value:  fmt.Sprintf("```\n%s\n```", tech),
			Inline: false,
		})
	}

	return m.discordConfig.sendRichDiscordNotification(
		fmt.Sprintf("New Subdomains Discovered for %s", domain),
		fmt.Sprintf("Found %d new subdomains", len(newSubs)),
		fields,
		false,
	)
}

func (m *SubdomainMonitor) notifyError(domain string, err error) error {
	if !m.discordConfig.NotifyOnError {
		return nil
	}

	return m.discordConfig.sendRichDiscordNotification(
		"Subdomain Monitoring Error",
		fmt.Sprintf("Error monitoring domain %s: %v", domain, err),
		[]DiscordField{
			{
				Name:  "Domain",
				Value: domain,
			},
		},
		true,
	)
}

func (m *SubdomainMonitor) saveSubdomains(domain string, subdomains []string) error {
	domainDir := filepath.Join(m.outputDir, domain)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		return err
	}

	filepath := filepath.Join(domainDir, "subdomains.txt")
	existingSubs, _ := m.runCommand(fmt.Sprintf("cat %s", filepath))

	subMap := make(map[string]bool)
	for _, sub := range existingSubs {
		subMap[sub] = true
	}

	var newSubs []string
	techInfo := make(map[string]string)

	for _, sub := range subdomains {
		if !subMap[sub] {
			newSubs = append(newSubs, sub)
			
			// Analyze technologies in a goroutine to speed up the process
			go func(s string) {
				tech, err := m.analyzeTechnologies(s)
				if err == nil {
					techInfo[s] = tech
				}
				m.takeScreenshot(s)
			}(sub)
		}
	}

	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, sub := range subdomains {
		file.WriteString(sub + "\n")
	}

	return m.notifyNewSubdomains(domain, newSubs, techInfo)
}

func (m *SubdomainMonitor) monitorSubdomains() {
	for {
		var wg sync.WaitGroup
		
		// Download dependencies
		files := []struct {
			url  string
			path string
		}{
			{resolversURL, m.resolversFile},
			{wordlistURL, m.wordlistFile},
			{permutationsURL, m.permutationsFile},
		}

		for _, file := range files {
			wg.Add(1)
			go func(url, path string) {
				defer wg.Done()
				m.downloadFile(url, path)
			}(file.url, file.path)
		}
		wg.Wait()

		// Monitor each domain concurrently
		for _, domain := range m.domainsToMonitor {
			wg.Add(1)
			go func(domain string) {
				defer wg.Done()
				m.logger.Printf("Scanning for subdomains of %s", domain)
				
				foundSubs, err := m.findSubdomains(domain)
				if err != nil {
					m.logger.Printf("Error finding subdomains for %s: %v", domain, err)
					m.notifyError(domain, err)
					return
				}
				
				if err := m.saveSubdomains(domain, foundSubs); err != nil {
					m.logger.Printf("Error saving subdomains for %s: %v", domain, err)
					m.notifyError(domain, err)
				}
				
				m.logger.Printf("Found and saved %d subdomains for %s", len(foundSubs), domain)
			}(domain)
		}
		wg.Wait()

		m.logger.Printf("Sleeping for %v...", checkInterval)
		time.Sleep(checkInterval)
	}
}

func main() {
	outputDir := flag.String("o", "results", "Output directory for results")
	listFile := flag.String("l", "", "File containing list of domains")
	
	// Discord-specific flags
	discordWebhook := flag.String("webhook", "", "Discord webhook URL (overrides env variable)")
	notifyNewSubs := flag.Bool("notify-new", true, "Notify on new subdomains")
	notifyErrors := flag.Bool("notify-errors", true, "Notify on errors")
	minSubCount := flag.Int("min-subs", 1, "Minimum number of subdomains to trigger notification")
	customUsername := flag.String("discord-username", "Subdomain Monitor", "Custom Discord bot username")
	showWebhookHelp := flag.Bool("webhook-help", false, "Show how to configure Discord webhook")
	
	flag.Parse()

	if *showWebhookHelp {
		fmt.Println("Discord Webhook Configuration:")
		fmt.Println("1. Set via environment variable:")
		fmt.Println("   export DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...")
		fmt.Println("2. Modify the DEFAULT_DISCORD_WEBHOOK constant in the source code")
		fmt.Println("3. Pass webhook via command-line flag:")
		fmt.Println("   ./subdomain_monitor -webhook https://discord.com/api/webhooks/...")
		os.Exit(0)
	}

	// Create Discord configuration
	discordConfig := NewDiscordNotificationConfig()
	
	// Override with command-line flags if provided
	if *discordWebhook != "" {
		discordConfig.WebhookURL = *discordWebhook
	}
	discordConfig.NotifyOnNewSubs = *notifyNewSubs
	discordConfig.NotifyOnError = *notifyErrors
	discordConfig.NotifyMinSubCount = *minSubCount
	discordConfig.Username = *customUsername

	var domains []string
	if *listFile != "" {
		file, err := os.Open(*listFile)
		if err != nil {
			log.Fatalf("Failed to open domain list file: %v", err)
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

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	monitor := NewSubdomainMonitor(domains, *outputDir, discordConfig)
	monitor.monitorSubdomains()
}
