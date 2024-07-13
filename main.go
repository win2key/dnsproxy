package main

import (
	"log"
	"net"
	"os"

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
		log.Printf("Received query for %s\n", question.Name)
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
				log.Printf("Domain not found in memory, querying 8.8.8.8: %s\n", domain)
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

func main() {
	// Setup logging to a file
	f, err := os.OpenFile("dnsproxy.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Error opening log file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)

	// Setup the DNS server
	dns.HandleFunc(".", handleDNSRequest)

	// Listen on UDP
	udpServer := &dns.Server{
		Addr: "127.0.0.1:53",
		Net:  "udp",
	}

	go func() {
		log.Printf("Starting UDP DNS server on %s", udpServer.Addr)
		err = udpServer.ListenAndServe()
		if err != nil {
			log.Fatalf("Failed to start UDP DNS server: %s\n", err.Error())
		}
	}()

	// Listen on TCP
	tcpServer := &dns.Server{
		Addr: "127.0.0.1:53",
		Net:  "tcp",
	}

	log.Printf("Starting TCP DNS server on %s", tcpServer.Addr)
	err = tcpServer.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start TCP DNS server: %s\n", err.Error())
	}
}
