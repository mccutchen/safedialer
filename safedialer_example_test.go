package safedialer_test

import (
	"fmt"
	"net"
	"net/http"

	"github.com/mccutchen/safedialer"
)

// Example demonstrates basic usage and functionality of safedialer.Control.
func Example() {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Control: safedialer.Control,
			}).DialContext,
		},
	}

	urls := []string{
		// safe request to 3rd party web site
		"https://httpbingo.org/status/201",

		// unsafe request, resolves to an internal IP address that might expose
		// sensitive information about your infrastructure
		"http://www.10.0.0.1.nip.io",
	}
	for _, url := range urls {
		resp, err := client.Get(url)
		printResponse(url, resp, err)
	}

	// Output:
	// https://httpbingo.org/status/201
	// ✅ 201 Created
	//
	// http://www.10.0.0.1.nip.io
	// ❌ Get "http://www.10.0.0.1.nip.io": dial tcp 10.0.0.1:80: unsafe IP address
}

func printResponse(url string, resp *http.Response, err error) {
	if err != nil {
		fmt.Printf("%s\n❌ %s\n\n", url, err)
	} else {
		fmt.Printf("%s\n✅ %s\n\n", url, resp.Status)
	}
}
