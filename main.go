package main

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

	results, _ := checkDomains(config, domains)

	criticalMatches := make([]result, 0)
	potentialMatches := make([]result, 0)

	for _, result := range results.DomainsWithCnames {
		if matched := matchFingerprints(result); matched != nil {
			if matched.Immediate {
				criticalMatches = append(criticalMatches, result)
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
}
