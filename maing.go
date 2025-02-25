package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
)

// VTError represents an error returned by the VirusTotal API.
type VTError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// VTData represents each subdomain record in the response.
type VTData struct {
	ID string `json:"id"`
}

// VTLinks holds the pagination information.
type VTLinks struct {
	Next string `json:"next"`
}

// VTResponse represents the structure of the API response.
type VTResponse struct {
	Data  []VTData `json:"data"`
	Links VTLinks  `json:"links"`
	Error *VTError `json:"error"`
}

func main() {
	// Parse command-line flag
	domainPtr := flag.String("d", "", "Domain to query (e.g., domain.com)")
	flag.Parse()
	if *domainPtr == "" {
		fmt.Println("Usage: -d domain.com")
		os.Exit(1)
	}
	domain := *domainPtr

	// Get API keys from environment variables
	var apiKeys []string
	if key := os.Getenv("VT_API_KEY"); key != "" {
		apiKeys = append(apiKeys, key)
	}
	if key := os.Getenv("VT_API_KEY2"); key != "" {
		apiKeys = append(apiKeys, key)
	}
	if key := os.Getenv("VT_API_KEY3"); key != "" {
		apiKeys = append(apiKeys, key)
	}
	if len(apiKeys) == 0 {
		log.Fatal("No API keys provided in environment variables (VT_API_KEY, VT_API_KEY2, VT_API_KEY3)")
	}

	currentKeyIndex := 0
	currentKey := apiKeys[currentKeyIndex]

	// Build the initial URL
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40", domain)

	// Use a map to accumulate unique subdomains
	uniqueSubdomains := make(map[string]struct{})
	client := &http.Client{}

	for url != "" {
		attempt := 0
		var vtResp VTResponse

		// Inner loop to handle quota errors by switching API keys
		for {
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				log.Fatalf("Error creating request: %v", err)
			}
			req.Header.Set("x-apikey", currentKey)

			resp, err := client.Do(req)
			if err != nil {
				log.Fatalf("HTTP request error: %v", err)
			}
			body, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				log.Fatalf("Error reading response body: %v", err)
			}

			err = json.Unmarshal(body, &vtResp)
			if err != nil {
				log.Printf("JSON unmarshal error: %v", err)
				log.Printf("Response body: %s", string(body))
				break
			}

			// Check for quota error
			if vtResp.Error != nil && vtResp.Error.Code == "QuotaExceededError" {
				log.Printf("API key %s quota exceeded, switching API key...\n", currentKey)
				currentKeyIndex = (currentKeyIndex + 1) % len(apiKeys)
				currentKey = apiKeys[currentKeyIndex]
				attempt++
				if attempt >= len(apiKeys) {
					log.Fatal("All API keys exhausted, exiting.")
				}
				continue // retry with the new key
			}
			break // valid response obtained
		}

		// Process the response: add subdomains that contain the domain (case-insensitive)
		if len(vtResp.Data) == 0 {
			log.Printf("No subdomains found in the response.\n")
		} else {
			for _, d := range vtResp.Data {
				if strings.Contains(strings.ToLower(d.ID), strings.ToLower(domain)) {
					uniqueSubdomains[d.ID] = struct{}{}
				}
			}
		}

		// Update URL with the "next" link (empty string if no further pages)
		url = vtResp.Links.Next
	}

	// Extract keys, sort, and print unique subdomains
	var subs []string
	for sub := range uniqueSubdomains {
		subs = append(subs, sub)
	}
	sort.Strings(subs)
	for _, sub := range subs {
		fmt.Println(sub)
	}
}
