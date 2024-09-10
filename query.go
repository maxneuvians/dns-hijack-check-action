package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Answer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type Job struct {
	Domain string
}

type Response struct {
	Status int      `json:"Status"`
	Answer []Answer `json:"Answer"`
}

type result struct {
	Domain   string
	Cnames   []string
	Nxdomain bool
	Status   int
}

type resultSet struct {
	DomainsWithCnames []result
	DomainsTimedOut   []result
	DomainsNX         []result
	DomainsOther      []result
}

func checkDomains(c *Config, domains []string) (resultSet, error) {
	client := http.Client{
		Timeout: time.Duration(c.HTTPTimeout) * time.Second,
	}

	resultSet := resultSet{
		DomainsWithCnames: []result{},
		DomainsTimedOut:   []result{},
		DomainsNX:         []result{},
		DomainsOther:      []result{},
	}

	jobs := make(chan Job, len(domains))
	results := make(chan result, len(domains))
	var wg sync.WaitGroup

	// Start workers
	for w := 0; w < c.Concurrency; w++ {
		go func(jobs <-chan Job, results chan<- result, wg *sync.WaitGroup) {
			for job := range jobs {
				cnames, nxdomain, status := checkDomain(client, job.Domain)
				results <- result{Domain: job.Domain, Cnames: cnames, Nxdomain: nxdomain, Status: status}
				wg.Done()
			}
		}(jobs, results, &wg)
	}

	wg.Add(len(domains))

	// Start timer
	now := time.Now()

	for _, domain := range domains {
		jobs <- Job{Domain: domain}
	}

	close(jobs)
	wg.Wait()

	for i := 0; i < len(domains); i++ {
		res := <-results

		switch true {
		case len(res.Cnames) > 0:
			resultSet.DomainsWithCnames = append(resultSet.DomainsWithCnames, res)
		case res.Status == 2:
			resultSet.DomainsTimedOut = append(resultSet.DomainsTimedOut, res)
		case res.Nxdomain:
			resultSet.DomainsNX = append(resultSet.DomainsNX, res)
		default:
			resultSet.DomainsOther = append(resultSet.DomainsOther, res)
		}
	}

	elapsed := time.Since(now)

	c.Logger.Info().Int("Domains checked", len(domains)).Msg("Finished checking domains")
	c.Logger.Info().Str("Time taken", elapsed.String()).Msg("Time taken to check domains")
	c.Logger.Info().
		Int("Domains with CNAMEs", len(resultSet.DomainsWithCnames)).
		Int("Domains with NXDOMAIN", len(resultSet.DomainsNX)).
		Int("Domains with other records", len(resultSet.DomainsOther)).
		Int("Domains that timed out", len(resultSet.DomainsTimedOut)).
		Msg("Domains with CNAMEs")
	return resultSet, nil
}

func checkDomain(client http.Client, domain string) ([]string, bool, int) {
	var cnames []string

	url := "https://dns.google/resolve?name=" + domain
	resp, err := client.Get(url)

	if err != nil {
		return nil, false, 2
	}

	defer resp.Body.Close()

	var response Response

	err = json.NewDecoder(resp.Body).Decode(&response)

	if err != nil {
		return nil, false, 2
	}

	for _, answer := range response.Answer {
		if answer.Type == 5 {
			cname := strings.Trim(answer.Data, ".")
			cnames = append(cnames, cname)
		}
	}

	if response.Status == 3 {
		return cnames, true, 3
	}

	return cnames, false, response.Status
}

func checkASUIDRecord(c *Config, domain string) bool {
	client := http.Client{
		Timeout: time.Duration(c.HTTPTimeout) * time.Second,
	}
	url := "https://dns.google/resolve?name=asuid." + domain + "&type=TXT"
	resp, err := client.Get(url)

	if err != nil {
		return false
	}

	defer resp.Body.Close()

	var response Response

	err = json.NewDecoder(resp.Body).Decode(&response)

	if err != nil {
		return false
	}

	if len(response.Answer) == 0 {
		return false
	}

	return true
}
