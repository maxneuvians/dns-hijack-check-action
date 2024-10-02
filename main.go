package main

import "regexp"

type stats struct {
	TotalDomains int    `json:"total_domains"`
	Elapsed      string `json:"elapsed"`
}

func main() {
	// Initialize configuration
	config := initConfig()

	config.Logger.Info().Msg("Starting DNS Hijack Check")

	// Parse the domain name file
	domains, err := parseFile(config)

	if err != nil {
		config.Logger.Fatal().Err(err).Msg("Failed to parse domain name file")
	}

	config.Logger.Info().Int("Domains parsed", len(domains)).Str("File name", config.DomainNameFile).Msg("Parsed domain name file")

	results, elapsed, _ := checkDomains(config, domains)

	criticalMatches := make([]result, 0)
	potentialMatches := make([]result, 0)

	var trafficManagerRegex = regexp.MustCompile(`^[^.]+\.trafficmanager\.net$`)

	for _, result := range results.DomainsWithCnames {
		if matched := matchFingerprints(result); matched != nil {
			if matched.Immediate {
				// Secondary check for certain Azure services
				switch true {
				case matched.AzureAppService:
					if azureMatched := checkASUIDRecord(config, matched.Domain); azureMatched {
						potentialMatches = append(potentialMatches, result)
					} else {
						criticalMatches = append(criticalMatches, result)
					}
				case matched.AzureTrafficManager:
					// Check if the domain is a top level traffic manager domain ex. example.trafficmanager.net
					if trafficManagerRegex.MatchString(matched.Domain) {
						criticalMatches = append(criticalMatches, result)
					} else {
						potentialMatches = append(potentialMatches, result)
					}
				default:
					criticalMatches = append(criticalMatches, result)
				}
			} else {
				potentialMatches = append(potentialMatches, result)
			}
		}
	}

	if len(criticalMatches) > 0 {
		config.Logger.Error().Int("Critical matches", len(criticalMatches)).Msg("Critical matches found")
		err = writeFile("critical.json", criticalMatches)
		if err != nil {
			config.Logger.Fatal().Err(err).Msg("Failed to write critical matches to file")
		}

	}

	if len(potentialMatches) > 0 {
		config.Logger.Warn().Int("Potential matches", len(potentialMatches)).Msg("Potential matches found")
		err = writeFile("potential.json", potentialMatches)
		if err != nil {
			config.Logger.Fatal().Err(err).Msg("Failed to write potential matches to file")
		}
	}

	// Write stats to file
	stats := stats{
		TotalDomains: len(domains),
		Elapsed:      elapsed.String(),
	}

	err = writeStats("stats.json", stats)

	if err != nil {
		config.Logger.Fatal().Err(err).Msg("Failed to write stats to file")
	}
}
