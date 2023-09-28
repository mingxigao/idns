package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/likexian/doh-go"
	hdns "github.com/likexian/doh-go/dns"
	"github.com/miekg/dns"
)

var mutex = &sync.Mutex{}
var records = make(map[string][]string) // Global map to hold DNS records
const IDNS_DEBUG = "IDNS_DEBUG"
const DEBUG_PREFIX = "[DEBUG]"

func isDebug() bool {
	return os.Getenv(IDNS_DEBUG) == "1"
}

func loadCache(cachePath string) {
	if cachePath == "" {
		return
	}
	file, err := os.Open(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("cache file not found. Creating a new one.")
			_, err := os.Create(cachePath)
			if err != nil {
				log.Fatal("Failed to create cache file: ", err)
			}
		} else {
			log.Fatal("Failed to read cache file: ", err)
		}
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " ")
		if len(parts) < 2 {
			log.Printf("Invalid line in config file: %s", line)
			continue
		}
		domain := parts[0]
		ips := parts[1:]
		updateRecords(domain, ips, "")
	}

	if err := scanner.Err(); err != nil {
		log.Fatal("Error reading config file: ", err)
	}
}

func saveCache(cachePath string) {
	file, err := os.Create(cachePath)
	if err != nil {
		log.Fatal("Failed to write config file: ", err)
	}
	defer file.Close()
	for domain, ips := range records {
		line := fmt.Sprintf("%s %s\n", domain, strings.Join(ips, " "))
		_, err := file.WriteString(line)
		if err != nil {
			log.Fatal("Failed to write line to config file: ", err)
		}
	}
}

func fetchRecordFromUpsteams(name string, upstreams []string) []string {
	var r *dns.Msg
	var err error
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	for i, us := range upstreams {
		r, _, err = c.Exchange(m, us)
		if err != nil {
			if i == len(upstreams)-1 {
				log.Printf("Error querying from upstreams: %s %s", name, err)
				return nil
			}
		} else {
			if isDebug() {
				fmt.Printf("[DEBUG] udp[%s] ", us)
			}
			break
		}
	}
	if r == nil {
		log.Println("No record found for", name)
		return nil
	}
	var ips []string
	for _, answer := range r.Answer {
		if a, ok := answer.(*dns.A); ok {
			if isDebug() {
				fmt.Printf(" %v \n", a)
			}
			ips = append(ips, a.A.String())
		}
	}

	return ips
}

func fetchRecordFromDNSProviders(name string, upstreams []string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// init doh client, auto select the fastest provider base on your like
	// you can also use as: c := doh.Use(), it will select from all providers
	c := doh.Use(doh.Quad9Provider, doh.CloudflareProvider, doh.GoogleProvider)
	defer c.Close()
	// do doh query
	rsp, err := c.Query(ctx, hdns.Domain(name), hdns.TypeA)
	if err != nil {
		if isDebug() {
			log.Println(DEBUG_PREFIX, name, err)
		}
		return fetchRecordFromUpsteams(name, upstreams)
	}
	// doh dns answer
	answer := rsp.Answer
	// print all answer
	var ips []string

	for _, a := range answer {
		if isDebug() {
			fmt.Printf("[DEBUG] doh %s -> %s\n", a.Name, a.Data)
		}
		ips = append(ips, a.Data)
	}

	return ips
}

func updateRecords(name string, ips []string, cachePath string) {
	mutex.Lock()
	records[name] = ips
	if cachePath != "" {
		saveCache(cachePath)
	}
	mutex.Unlock()
}

func (h *dnsHandler) parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			if isDebug() {
				log.Printf("[DEBUG] query %s\n", q.Name)
			}
			ips := records[q.Name]
			if len(ips) == 0 {
				if h.pacRules[q.Name] {
					if isDebug() {
						log.Println("[DEBUG] hit pac rule")
					}
					ips = fetchRecordFromDNSProviders(q.Name, h.pacUpstreams)
				} else {
					ips = fetchRecordFromUpsteams(q.Name, h.nonPacUpStreams)
				}
				if len(ips) > 0 {
					go updateRecords(q.Name, ips, h.cachePath)
				}
			}
			for _, ip := range ips {
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
	}
}

type dnsHandler struct {
	pacUpstreams    []string
	cachePath       string
	pacRules        map[string]bool
	nonPacUpStreams []string
}

func (h *dnsHandler) parsePacFile(pacPath string) {
	if pacPath == "" {
		return
	}
	file, err := os.Open(pacPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("pac file is not found.")
		}
		return
	}
	defer file.Close()
	h.pacRules = make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		h.pacRules[line+"."] = true
	}
	if isDebug() {
		log.Println("[DEBUG] PAC rules:\n", h.pacRules)
	}
}

func (h *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		h.parseQuery(m)
	}

	w.WriteMsg(m)
}

func main() {
	var cachePath, addr, pacPath, upStreams string
	flag.StringVar(&addr, "addr", ":5353", "Address for DNS server") // Allow user to specify port via command line
	flag.StringVar(&pacPath, "pac", "", "The file path to pac")
	flag.StringVar(&cachePath, "cache", "", "The file path to pac")
	flag.StringVar(&upStreams, "upstreams", "114.114.114.114:53,8.8.8.8:53", "dns upstreams for domains are not in pac")
	flag.Parse()

	// Load existing records from cache
	loadCache(cachePath)
	handler := &dnsHandler{cachePath: cachePath, pacUpstreams: []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53", "114.114.114.114:53"}}
	handler.nonPacUpStreams = strings.Split(upStreams, ",")

	handler.parsePacFile(pacPath)
	if isDebug() {
		fmt.Println(DEBUG_PREFIX, handler.nonPacUpStreams)
	}
	server := &dns.Server{
		Addr:      addr,
		Net:       "udp",
		Handler:   handler,
		UDPSize:   65535,
		ReusePort: true,
	}
	log.Printf("Starting at %s\n", addr)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}

}
