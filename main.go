package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// In-memory DNS records
var dnsRecords = map[string]string{
	"example.com.": "1.2.3.4",
	"test.com.":    "5.6.7.8",
}

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
				// log.Printf("Domain not found in memory, querying 8.8.8.8: %s\n", domain)
				// Forward to 8.8.8.8
				c := new(dns.Client)
				in, _, err := c.Exchange(r, "8.8.8.8:53")
				if err != nil {
					log.Printf("Error querying 8.8.8.8: %v", err)
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
		cmd = exec.Command("networksetup", "-setdnsservers", "Wi-Fi", "127.0.0.1")
	case "linux":
		cmd = exec.Command("nmcli", "device", "modify", "eth0", "ipv4.dns", "127.0.0.1")
	case "windows":
		cmd = exec.Command("powershell", "Set-DnsClientServerAddress", "-InterfaceAlias", "\"Wi-Fi\"", "-ServerAddresses", "127.0.0.1")
	default:
		log.Fatalf("Unsupported OS: %s", runtime.GOOS)
	}
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Failed to set DNS on start: %v", err)
	}
	log.Printf("DNS set to 127.0.0.1 on start")
}

func resetDNSOnExit() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("networksetup", "-setdnsservers", "Wi-Fi", "empty")
	case "linux":
		cmd = exec.Command("nmcli", "device", "modify", "eth0", "ipv4.ignore-auto-dns", "yes")
	case "windows":
		cmd = exec.Command("powershell", "Set-DnsClientServerAddress", "-InterfaceAlias", "\"Wi-Fi\"", "-ResetServerAddresses")
	default:
		log.Fatalf("Unsupported OS: %s", runtime.GOOS)
	}
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Failed to reset DNS on exit: %v", err)
	}
	log.Printf("DNS reset to default on exit")
}

func main() {
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
	udpServer := &dns.Server{
		Addr: "127.0.0.1:53",
		Net:  "udp",
	}

	// Listen on TCP
	tcpServer := &dns.Server{
		Addr: "127.0.0.1:53",
		Net:  "tcp",
	}

	go func() {
		log.Printf("Starting UDP DNS server on %s", udpServer.Addr)
		if err := udpServer.ListenAndServe(); err != nil {
			log.Printf("Failed to start UDP DNS server: %s\n", err.Error())
			sigs <- syscall.SIGTERM
		}
	}()

	go func() {
		log.Printf("Starting TCP DNS server on %s", tcpServer.Addr)
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Printf("Failed to start TCP DNS server: %s\n", err.Error())
			sigs <- syscall.SIGTERM
		}
	}()

	sig := <-sigs
	log.Printf("Received signal: %v", sig)

	// Shutdown the DNS servers with a timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := udpServer.ShutdownContext(ctx); err != nil {
		log.Printf("Failed to gracefully shutdown UDP server: %v", err)
	}

	if err := tcpServer.ShutdownContext(ctx); err != nil {
		log.Printf("Failed to gracefully shutdown TCP server: %v", err)
	}

	log.Println("Exiting program")
}
