package main

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
)

func parseFile(c *Config) ([]string, error) {
	file, err := os.Open(c.DomainNameFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if !strings.HasPrefix(scanner.Text(), "*") {
			domains = append(domains, scanner.Text())
		}
	}

	return domains, nil
}

func writeFile(filename string, results []result) error {
	if len(results) == 0 {
		return nil
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write the results to the file as JSON
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(results)
	if err != nil {
		return err
	}

	return nil
}
