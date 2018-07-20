package main

import (
	"strings"
	"testing"
)

func TestHostParse(t *testing.T) {

	zones := strings.NewReader(
		`
golem.de:32670b5b64b12c9c80f2fab02cd5eed2b8bb01c9:
heise.de:nichtsda:www
google.com:anything:all,everybody,www
`)

	zonesToExpect, toExpects, zoneSubsIncl := parseHostFile(zones, false)

	if len(zonesToExpect) != 3 {
		t.Error("Too less zones in parsed file")
	}

	if len(toExpects) != 3 {
		t.Error("Too less checksums found in parsed rows")
	}

	if len(zoneSubsIncl) != 3 {
		t.Error("Too less subdomains in parsed rows")
	}

	if toExpects["golem.de."] != "32670b5b64b12c9c80f2fab02cd5eed2b8bb01c9" {
		t.Error("Wrong checksum for golem.de in parsed row")
	}

	if zoneSubsIncl["heise.de."] != "www" {
		t.Error("Subodmains for heise.de not found in parsed row")
	}

	if zoneSubsIncl["google.com."] != "all,everybody,www" {
		t.Error("Subodmains for google.com not found in parsed row")
	}

	if zonesToExpect["google.com."][0] != "google.com." {
		t.Error("google.com. ist is not first entry in the google.com. slice")
	}

	if zonesToExpect["google.com."][1] != "all.google.com." {
		t.Error("all.google.com. is not second entry in the google.com. slice")
	}

	if zonesToExpect["google.com."][3] != "www.google.com." {
		t.Error("www.google.com. is not fourth entry in the google.com. slice")
	}

}
