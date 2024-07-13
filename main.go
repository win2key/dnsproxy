package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// In-memory DNS records
var dnsRecords = map[string]string{
	"example.com.": "1.2.3.4",
	"test.com.":    "5.6.7.8",
}

var forwardDNS string

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	msg.Authoritative = true

	for _, question := range r.Question {
		log.Printf(": %s\n", question.Name)
		if question.Qtype == dns.TypeA {
			domain := question.Name
			ip, found := dnsRecords[domain]
			if found {
				log.Printf("Domain found in memory: %s -> %s\n", domain, ip)
				rr := &dns.A{
					Hdr: dns.RR_Header{
						Name:   domain,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    3600,
					},
					A: net.ParseIP(ip),
				}
				msg.Answer = append(msg.Answer, rr)
			} else {
				// log.Printf("Domain not found in memory, querying %s: %s\n", forwardDNS, domain)
				// Forward to detected DNS server
				c := new(dns.Client)
				in, _, err := c.Exchange(r, forwardDNS)
				if err != nil {
					log.Printf("Error querying %s: %v", forwardDNS, err)
					dns.HandleFailed(w, r)
					return
				}
				msg.Answer = in.Answer
			}
		}
	}

	w.WriteMsg(&msg)
}

func setDNSOnStart() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("networksetup", "-setdnsservers", "Wi-Fi", "127.0.0.1", "::1")
	case "linux":
		cmd = exec.Command("nmcli", "device", "modify", "eth0", "ipv4.dns", "127.0.0.1", "ipv6.dns", "::1")
	case "windows":
		cmd = exec.Command("powershell", "Set-DnsClientServerAddress", "-InterfaceAlias", "\"Wi-Fi\"", "-ServerAddresses", "127.0.0.1,::1")
	default:
		log.Fatalf("Unsupported OS: %s", runtime.GOOS)
	}
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Failed to set DNS on start: %v", err)
	}
	log.Printf("Bind DNS (on start)")
}

func resetDNSOnExit() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("networksetup", "-setdnsservers", "Wi-Fi", "empty")
	case "linux":
		cmd = exec.Command("nmcli", "device", "modify", "eth0", "ipv4.ignore-auto-dns", "yes", "ipv6.ignore-auto-dns", "yes")
	case "windows":
		cmd = exec.Command("powershell", "Set-DnsClientServerAddress", "-InterfaceAlias", "\"Wi-Fi\"", "-ResetServerAddresses")
	default:
		log.Fatalf("Unsupported OS: %s", runtime.GOOS)
	}
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Failed to reset DNS on exit: %v", err)
	}
	log.Printf("Release DNS (on exit)")
}

func detectSystemDNS() string {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("scutil", "--dns")
	case "linux":
		cmd = exec.Command("nmcli", "device", "show")
	case "windows":
		cmd = exec.Command("powershell", "Get-DnsClientServerAddress")
	default:
		log.Fatalf("Unsupported OS: %s", runtime.GOOS)
	}
	output, err := cmd.Output()
	if err != nil {
		log.Fatalf("Failed to detect system DNS: %v", err)
	}
	return parseDNSServer(output)
}

func parseDNSServer(output []byte) string {
	lines := strings.Split(string(output), "\n")
	switch runtime.GOOS {
	case "darwin":
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "nameserver[0]") {
				parts := strings.Fields(line)
				if len(parts) > 2 {
					return parts[2] + ":53"
				}
			}
		}
	case "linux":
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "IP4.DNS") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					return parts[1] + ":53"
				}
			}
		}
	case "windows":
		var ipv4DNS, ipv6DNS string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Wi-Fi") {
				for _, nextLine := range lines {
					if strings.HasPrefix(nextLine, "Wi-Fi") {
						if strings.Contains(nextLine, "IPv4") && strings.Contains(nextLine, "{") {
							ipv4DNS = strings.Trim(nextLine[strings.Index(nextLine, "{")+1:strings.Index(nextLine, "}")], " ")
						}
						if strings.Contains(nextLine, "IPv6") && strings.Contains(nextLine, "{") {
							ipv6DNS = strings.Trim(nextLine[strings.Index(nextLine, "{")+1:strings.Index(nextLine, "}")], " ")
						}
					}
				}
				if ipv4DNS != "" {
					return ipv4DNS + ":53"
				}
				if ipv6DNS != "" {
					return "[" + ipv6DNS + "]:53"
				}
			}
		}
	}
	return "8.8.8.8:53" // Default to Google DNS if detection fails
}

func main() {
	// Detect current DNS server
	forwardDNS = detectSystemDNS()
	log.Printf("DNS forwarder: %s\n", forwardDNS)

	// Set DNS on start
	setDNSOnStart()

	// Ensure DNS is reset on exit
	defer resetDNSOnExit()

	// Setup signal handling to catch interrupts and properly exit
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Setup the DNS server
	dns.HandleFunc(".", handleDNSRequest)

	// Listen on UDP
	udpServerIPv4 := &dns.Server{
		Addr: "127.0.0.1:53",
		Net:  "udp",
	}

	udpServerIPv6 := &dns.Server{
		Addr: "[::1]:53",
		Net:  "udp",
	}

	// Listen on TCP
	tcpServerIPv4 := &dns.Server{
		Addr: "127.0.0.1:53",
		Net:  "tcp",
	}

	tcpServerIPv6 := &dns.Server{
		Addr: "[::1]:53",
		Net:  "tcp",
	}

	go func() {
		log.Printf("... UDP listener on %s", udpServerIPv4.Addr)
		if err := udpServerIPv4.ListenAndServe(); err != nil {
			log.Printf("Failed to start UDP DNS server: %s\n", err.Error())
			sigs <- syscall.SIGTERM
		}
	}()

	go func() {
		log.Printf("... UDP listener on %s", udpServerIPv6.Addr)
		if err := udpServerIPv6.ListenAndServe(); err != nil {
			log.Printf("Failed to start UDP DNS server: %s\n", err.Error())
			sigs <- syscall.SIGTERM
		}
	}()

	go func() {
		log.Printf("... TCP listener on %s", tcpServerIPv4.Addr)
		if err := tcpServerIPv4.ListenAndServe(); err != nil {
			log.Printf("Failed to start TCP DNS server: %s\n", err.Error())
			sigs <- syscall.SIGTERM
		}
	}()

	go func() {
		log.Printf("... TCP listener on %s", tcpServerIPv6.Addr)
		if err := tcpServerIPv6.ListenAndServe(); err != nil {
			log.Printf("Failed to start TCP DNS server: %s\n", err.Error())
			sigs <- syscall.SIGTERM
		}
	}()

	sig := <-sigs
	log.Printf("Received signal: %v", sig)

	// Shutdown the DNS servers with a timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := udpServerIPv4.ShutdownContext(ctx); err != nil {
		log.Printf("Failed to gracefully shutdown UDP server: %v", err)
	}

	if err := udpServerIPv6.ShutdownContext(ctx); err != nil {
		log.Printf("Failed to gracefully shutdown UDP server: %v", err)
	}

	if err := tcpServerIPv4.ShutdownContext(ctx); err != nil {
		log.Printf("Failed to gracefully shutdown TCP server: %v", err)
	}

	if err := tcpServerIPv6.ShutdownContext(ctx); err != nil {
		log.Printf("Failed to gracefully shutdown TCP server: %v", err)
	}

	log.Println("Exiting program")
}
