package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
)

type dnsResult struct {
	zoneName                                          string
	generatedCheckSum, expectedCheckSum, includedSubs string
	zone                                              []string
}

/* poor globals */
var nameServer string
var nameServerProto string = "udp"
var nagiosState = map[string]int{
	"OK":       0,
	"WARNING":  1,
	"CRITICAL": 2,
	"UNKNOWN":  3,
}

func main() {
	var file io.ReadWriteCloser
	var err error
	var zones []string
	var wg sync.WaitGroup
	var osExit int
	var osExitMessage, osWarnMessage string
	var dnsResults = make(chan dnsResult, len(zones))
	var r net.Resolver

	hostFile := flag.String("hostfile", "hosts", "Zones to check")
	flag.StringVar(&nameServer, "nameserver", "", "Nameserver to use, else will use the default one")
	singleDomain := flag.String("single", "", "Single domain to check / print out")
	rebuildFile := flag.Bool("u", false, "if set, regenerate and update hostfile and update from generated checkSums")
	addDefaultHostname := flag.Bool("defaults", false, "guess and add default subdomains")
	printAll := flag.Bool("v", false, "print OK matches also")

	flag.Parse()

	if *hostFile == "" {
		log.Fatal("Need an input file")
	}

	if *singleDomain != "" {
		zones = append(zones, *singleDomain+":"+":")
		/* explicit set printAll */
		*printAll = true
	} else {

		if file, err = os.Open(*hostFile); err != nil {
			log.Fatal(err)
		}

		zones = parseHostFile(file)
		file.Close()
	}

	ctx := context.Background()

	if nameServer != "" {
		r = net.Resolver{
			Dial:     returnDialer,
			PreferGo: true,
		}
	} else {
		r = net.Resolver{}
	}

	for _, v := range zones {
		z := strings.Split(v, ":")
		wg.Add(1)

		go func() {

			if len(z) < 3 {
				checkZone(r, ctx, z[0], z[1], "", dnsResults, *addDefaultHostname)
			} else if len(z) == 3 {
				checkZone(r, ctx, z[0], z[1], z[2], dnsResults, *addDefaultHostname)
			}

			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(dnsResults)
	}()

	if *rebuildFile {
		file, err = os.OpenFile(*hostFile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal("Cant write hostfile")
		}
		defer file.Close()
	}

	for v := range dnsResults {
		if *rebuildFile {
			fmt.Fprintf(file, "%s:%s:%s\n", v.zoneName, v.generatedCheckSum, v.includedSubs)
		} else {
			if *singleDomain != "" {
				osExitMessage += fmt.Sprintf("%d ZONE_%s - calc:%s\n", nagiosState["UNKNOWN"], v.zoneName, v.generatedCheckSum, v.zone)
			} else {
				if v.generatedCheckSum != v.expectedCheckSum {
					osWarnMessage += fmt.Sprintf("%d ZONE_%s - exp:%s calc: %s %s\n", nagiosState["WARNING"], v.zoneName, v.expectedCheckSum, v.generatedCheckSum, v.zone)
					osExit = 1
				} else {
					osExitMessage += fmt.Sprintf("%d ZONE_%s - calc:%s %s\n", nagiosState["OK"], v.zoneName, v.expectedCheckSum, v.zone)
				}
			}
		}
	}

	if osExit == 1 {
		fmt.Println(osWarnMessage)
	}
	if *printAll {
		fmt.Print(osExitMessage)
	}

	os.Exit(osExit)
}

func returnDialer(ctx context.Context, proto, server string) (net.Conn, error) {
	d := net.Dialer{}
	return d.DialContext(ctx, nameServerProto, nameServer+":53")
}

func checkZone(r net.Resolver, ctx context.Context, mainZone, checksum string, includeSubs string, dnsResults chan dnsResult, addDefaultHostnames bool) {
	var subDomain = make(map[string]bool)
	var zoneFile []string
	h := sha1.New()

	if !strings.HasSuffix(mainZone, ".") {
		mainZone += "."
	}

	zonesToCheck := append([]string{}, mainZone)

	/* Add magic default subDomains */
	if addDefaultHostnames {
		includeSubs += "," + defaultHostnames
	}
	subDomains := strings.Split(includeSubs, ",")
	for _, v := range subDomains {
		subDomain[v] = true
	}

	for k, _ := range subDomain {
		zonesToCheck = append(zonesToCheck, k+"."+mainZone)
	}

	sort.Strings(zonesToCheck)

	for _, zone := range zonesToCheck {
		if strings.HasPrefix(zone, "_") {
			cname, addrs, err := r.LookupSRV(ctx, "", "", zone)
			if err == nil {
				for _, v := range addrs {
					zoneFile = append(zoneFile, fmt.Sprintf("SRV: %s %s %d %d %d", cname, v.Target, v.Port, v.Priority, v.Weight))
				}
			}
			continue
		}

		mx, err := r.LookupMX(ctx, zone)
		if err == nil {
			for _, v := range mx {
				zoneFile = append(zoneFile, fmt.Sprintf("MX: %s %d ", v.Host, v.Pref))
			}
		}

		ns, err := r.LookupNS(ctx, zone)
		if err == nil {
			for _, v := range ns {
				zoneFile = append(zoneFile, "NS: "+v.Host)
			}
		}

		ip, err := r.LookupHost(ctx, zone)
		if err == nil {
			for _, v := range ip {
				zoneFile = append(zoneFile, "IP: "+v)
			}
		}

		txt, err := r.LookupTXT(ctx, zone)
		if err == nil {
			for _, v := range txt {
				zoneFile = append(zoneFile, "TXT: "+v)
			}
		}

		cname, err := r.LookupCNAME(ctx, zone)
		if err == nil {
			zoneFile = append(zoneFile, "CNAME: "+cname)
		}
		sort.Strings(zoneFile)
		for _, v := range zoneFile {
			io.WriteString(h, v)
		}
	}

	generatedCheckSum := fmt.Sprintf("%x", h.Sum(nil))
	dnsResults <- dnsResult{mainZone, generatedCheckSum, checksum, includeSubs, zoneFile}
	ctx.Done()

}

func parseHostFile(r io.Reader) (zones []string) {

	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		zones = append(zones, scanner.Text())
	}
	return
}
