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

/* zoneResult is the expected structure for
returning results over our go - channel after a successful lookup
*/
type zoneResult struct {
	name, sum string
	zone      []string
}

/* poor globals */
var states = map[string]int{
	"OK":       0,
	"WARNING":  1,
	"CRITICAL": 2,
	"UNKNOWN":  3,
}

func main() {
	/* predefined variable names */
	var err error
	var wg sync.WaitGroup
	var osExit int
	var exitMsg, warnMsg string
	var results = make(chan zoneResult)
	var fileOutput []string

	/* Command line parameter */
	hostFile := flag.String("hostfile", "checkDNShosts", "Zones to check")
	nameserver := flag.String("nameserver", "", "Nameserver to use, else will use the default one")
	addDefaultHostname := flag.Bool("defaults", false, "guess and add default subdomains")
	updateFile := flag.Bool("u", false, "update host file")
	printAll := flag.Bool("v", false, "print OK matches also")

	/* parse cli parameter */
	flag.Parse()

	if *hostFile == "" {
		log.Fatal("Need an input file")
	}

	/* open hostfile */
	file, err := os.Open(*hostFile)
	if err != nil {
		log.Fatal(err)
	}

	/* parse hostfile and return two values
	zonesToExpect => map of strings of []string with the mainzone as key, containing the parsed zones including subdomains
	toExpects => map of strings with the mainzone as key containing the expected chechsum result
	*/
	zonesToExpect, toExpects, zoneSubsIncl := parseHostFile(file, *addDefaultHostname)

	/* clean up file handle */
	file.Close()

	/* loop over the parsed zones and run a dns zone lookup for each */
	/* todo, maybe force a fixed upper limit on parallel go routines */
	for e := range zonesToExpect {
		wg.Add(1)
		go func(index string) {

			defer wg.Done()
			checkZone(*nameserver, zonesToExpect[index], results)

		}(e)
	}

	/* wait till all checkZone go routines have finished, then close the channel */
	go func() {
		wg.Wait()
		close(results)
	}()

	/* read out the channel and print output to stdout */
	for v := range results {

		if v.sum != toExpects[v.name] {
			warnMsg += fmt.Sprintf("%d ZONE_%s - exp:%s calc:%s zone:%s\n",
				states["WARNING"], v.name, toExpects[v.name], v.sum, v.zone)
			osExit = 1
		} else {
			exitMsg += fmt.Sprintf("%d ZONE_%s - calc:%s zone:%s\n",
				states["OK"], v.name, toExpects[v.name], v.zone)
		}

		/* do we need to re-generate the input file later? */
		if *updateFile {
			fileOutput = append(fileOutput, fmt.Sprintf("%s:%s:%s", v.name, toExpects[v.name], zoneSubsIncl[v.name]))
		}

	}

	/* different exit handling */
	if osExit == 1 {
		fmt.Println(warnMsg)
	}

	/* print all collected output, even the OK strings */
	if *printAll {
		fmt.Print(exitMsg)
	}

	/* update file if necessary */
	if *updateFile {

		/* TODO, if something failed, e.g. dns lookup, dont write a new file? */

		file, err := os.OpenFile(*hostFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Update file error: %s", err)
		}

		/* write write write */
		for _, v := range fileOutput {
			fmt.Fprintf(file, "%s\n", v)
		}

		/* close handle */
		file.Close()

	}
	os.Exit(osExit)
}

/*
CheckZone is called with an optional nameServer argument, a list of zones to lookup and
a channel to return the results
*/
func checkZone(nameServer string, zoneContent []string, dnsResults chan zoneResult) {
	var zoneFile []string
	var r net.Resolver

	/* not used context for dns lookup object */
	ctx := context.TODO()

	/* SHA1 bucket to write our zone info */
	h := sha1.New()

	/* create a resolver with a user nameserver as a dialer */
	if nameServer != "" {
		dialer := func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", nameServer+":53")
		}
		r = net.Resolver{Dial: dialer, PreferGo: true}
	} else {
		r = net.Resolver{}
	}

	/* loop over zoneContent and start creating dns queries */
	for _, zone := range zoneContent {
		/* some extra handling for SRV records */
		if strings.HasPrefix(zone, "_") {
			cname, addrs, err := r.LookupSRV(ctx, "", "", zone)
			if err == nil {
				for _, v := range addrs {
					zoneFile = append(zoneFile, fmt.Sprintf("SRV: %s %s %d %d %d", cname, v.Target, v.Port, v.Priority, v.Weight))
				}
			}
			continue
		}

		/* mx records */
		mx, err := r.LookupMX(ctx, zone)
		if err == nil {
			for _, v := range mx {
				zoneFile = append(zoneFile, fmt.Sprintf("MX: %s %d ", v.Host, v.Pref))
			}
		}

		/* NS records */
		ns, err := r.LookupNS(ctx, zone)
		if err == nil {
			for _, v := range ns {
				zoneFile = append(zoneFile, "NS: "+v.Host)
			}
		}

		/* ip and ipv6 records */
		ip, err := r.LookupHost(ctx, zone)
		if err == nil {
			for _, v := range ip {
				zoneFile = append(zoneFile, "IP: "+v)
			}
		}

		/* txt records */
		txt, err := r.LookupTXT(ctx, zone)
		if err == nil {
			for _, v := range txt {
				zoneFile = append(zoneFile, "TXT: "+v)
			}
		}

		/* cnames */
		cname, err := r.LookupCNAME(ctx, zone)
		if err == nil {
			zoneFile = append(zoneFile, "CNAME: "+cname)
		}

		/* mandatory:
		sort the file so the output of SHA1 is always the same, else will give random hashed
		*/
		sort.Strings(zoneFile)

		/* write output to sha1 bucket */
		for _, v := range zoneFile {
			io.WriteString(h, v)
		}
	}

	/* calculate checksum and printout in hex letters */
	generatedCheckSum := fmt.Sprintf("%x", h.Sum(nil))

	/* send result back over channel */
	dnsResults <- zoneResult{zoneContent[0], generatedCheckSum, zoneFile}

	/* close context if any was given */
	ctx.Done()

}

/* parseHostfile
reads out our hostfile row by row, easier than including a full csv parser
*/
func parseHostFile(r io.Reader, addDefaultHostnames bool) (map[string][]string, map[string]string, map[string]string) {
	/* our named return maps */
	zoneToChecks := map[string][]string{}
	checksumToExpect := map[string]string{}
	zoneSubsIncl := map[string]string{}

	scanner := bufio.NewScanner(r)

	/* loop over "csv" content */
	for scanner.Scan() {

		/* build a true table for subdomains */
		var subDomain = make(map[string]bool)
		z := strings.Split(scanner.Text(), ":")

		/* not enough input? then continue */
		if len(z) <= 1 {
			continue
		}

		/* prevent things like a local lookup */
		if !strings.HasSuffix(z[0], ".") {
			z[0] += "."
		}

		/* Too less input, then add a slice entry */
		if len(z) == 2 {
			z = append(z, "")
		}

		/* save our original list of subdomains */
		zoneSubsIncl[z[0]] = z[2]

		/* Add magic default subDomains */
		if addDefaultHostnames {
			z[2] += "," + defaultHostnames
		}

		/* Split all subdomains and build a map for uniqueness */
		subDomains := strings.Split(z[2], ",")
		for _, v := range subDomains {
			subDomain[v] = true
		}

		/* Add main zone */
		zoneToChecks[z[0]] = append(zoneToChecks[z[0]], z[0])

		/* Add sub domains */
		for k := range subDomain {
			zoneToChecks[z[0]] = append(zoneToChecks[z[0]], k+"."+z[0])
		}

		/* map checksum to mainzone-key */
		checksumToExpect[z[0]] = z[1]

		/* sort slice, else the results will be randomized */
		sort.Strings(zoneToChecks[z[0]])

		/* Add main zone in the beginning */
		zoneToChecks[z[0]] = append([]string{z[0]}, zoneToChecks[z[0]]...)
		/* jump back to scanner loop */
	}

	return zoneToChecks, checksumToExpect, zoneSubsIncl
}
