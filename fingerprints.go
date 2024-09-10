package main

import (
	"strings"
)

type fingerprint struct {
	cname       []string
	name        string
	nxdomain    bool
	fingerprint string
}

type vulnerableDomain struct {
	AzureAppService bool
	Domain          string
	Cname           []string
	Name            string
	Immediate       bool
}

var fingerprints = []fingerprint{
	{
		cname: []string{
			"elasticbeanstalk.com",
		},
		nxdomain:    true,
		name:        "AWS/Elastic Beanstalk",
		fingerprint: "NXDOMAIN",
	},
	{
		cname: []string{
			"s3.amazonaws.com",
		},
		nxdomain:    false,
		name:        "AWS/S3",
		fingerprint: "The specified bucket does not exist",
	},
	{
		cname: []string{
			"agilecrm.com",
		},
		nxdomain:    false,
		name:        "Agile CRM",
		fingerprint: "Sorry, this page is no longer available.",
	},
	{
		cname: []string{
			"airee.ru",
		},
		nxdomain:    false,
		name:        "Airee.ru",
		fingerprint: "Ошибка 402. Сервис Айри.рф не оплачен",
	},
	{
		cname: []string{
			"animaapp.io",
		},
		nxdomain:    false,
		name:        "Anima",
		fingerprint: "The page you were looking for does not exist.",
	},
	{
		cname: []string{
			"bitbucket.io",
		},
		nxdomain:    false,
		name:        "Bitbucket",
		fingerprint: "Repository not found",
	},
	{
		cname: []string{
			"trydiscourse.com",
		},
		nxdomain:    true,
		name:        "Discourse",
		fingerprint: "NXDOMAIN",
	},
	{
		cname: []string{
			"furyns.com",
		},
		nxdomain:    false,
		name:        "Gemfury",
		fingerprint: "404: This page could not be found.",
	},
	{
		cname: []string{
			"ghost.io",
		},
		nxdomain:    false,
		name:        "Ghost",
		fingerprint: "Site unavailable\\.&#124;Failed to resolve DNS path for this host",
	},
	{
		cname: []string{
			"hatenablog.com",
		},
		nxdomain:    false,
		name:        "HatenaBlog",
		fingerprint: "404 Blog is not found",
	},
	{
		cname: []string{
			"helpjuice.com",
		},
		nxdomain:    false,
		name:        "Help Juice",
		fingerprint: "We could not find what you're looking for.",
	},
	{
		cname: []string{
			"helpscoutdocs.com",
		},
		nxdomain:    false,
		name:        "Help Scout",
		fingerprint: "No settings were found for this company:",
	},
	{
		cname: []string{
			"helprace.com",
		},
		nxdomain:    false,
		name:        "Helprace",
		fingerprint: "HTTP_STATUS=301",
	},
	{
		cname: []string{
			"youtrack.cloud",
		},
		nxdomain:    false,
		name:        "JetBrains",
		fingerprint: "is not a registered InCloud YouTrack",
	},
	{
		cname: []string{
			"launchrock.com",
		},
		nxdomain:    false,
		name:        "LaunchRock",
		fingerprint: "HTTP_STATUS=500",
	},
	{
		cname: []string{
			"cloudapp.azure.com",
			"azurewebsites.net",
			"blob.core.windows.net",
			"cloudapp.azure.com",
			"azure-api.net",
			"azurehdinsight.net",
			"azureedge.net",
			"azurecontainer.io",
			"database.windows.net",
			"azuredatalakestore.net",
			"search.windows.net",
			"azurecr.io",
			"redis.cache.windows.net",
			"azurehdinsight.net",
			"servicebus.windows.net",
			"visualstudio.com",
		},
		nxdomain:    true,
		name:        "Microsoft Azure",
		fingerprint: "NXDOMAIN",
	},
	{
		cname: []string{
			"ngrok.io",
		},
		nxdomain:    false,
		name:        "Ngrok",
		fingerprint: "Tunnel .*.ngrok.io not found",
	},
	{
		cname: []string{
			"readme.io",
		},
		nxdomain:    false,
		name:        "Readme.io",
		fingerprint: "The creators of this project are still working on making everything perfect!",
	},
	{
		cname: []string{
			"52.16.160.97",
		},
		nxdomain:    false,
		name:        "SmartJobBoard",
		fingerprint: "This job board website is either expired or its domain name is invalid.",
	},
	{
		cname: []string{
			"s.strikinglydns.com",
		},
		nxdomain:    false,
		name:        "Strikingly",
		fingerprint: "PAGE NOT FOUND.",
	},
	{
		cname: []string{
			"na-west1.surge.sh",
		},
		nxdomain:    false,
		name:        "Surge.sh",
		fingerprint: "project not found",
	},
	{
		cname: []string{
			"surveysparrow.com",
		},
		nxdomain:    false,
		name:        "SurveySparrow",
		fingerprint: "Account not found.",
	},
	{
		cname: []string{
			"read.uberflip.com",
		},
		nxdomain:    false,
		name:        "Uberflip",
		fingerprint: "The URL you've accessed does not provide a hub.",
	},
	{
		cname: []string{
			"stats.uptimerobot.com",
		},
		nxdomain:    false,
		name:        "Uptimerobot",
		fingerprint: "page not found",
	},
	{
		cname: []string{
			"wordpress.com",
		},
		nxdomain:    false,
		name:        "Wordpress",
		fingerprint: "Do you want to register .*.wordpress.com?",
	},
	{
		cname: []string{
			"worksites.net",
			"69.164.223.206",
		},
		nxdomain:    false,
		name:        "Worksites",
		fingerprint: "Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist.",
	},
}

func matchFingerprints(r result) *vulnerableDomain {
	for _, fp := range fingerprints {
		for _, cname := range fp.cname {
			for _, c := range r.Cnames {
				if strings.HasSuffix(c, cname) {
					isAppService := false

					if cname == "azurewebsites.net" {
						isAppService = true
					}

					return &vulnerableDomain{
						AzureAppService: isAppService,
						Domain:          r.Domain,
						Cname:           r.Cnames,
						Name:            fp.name,
						Immediate:       r.Nxdomain,
					}
				}
			}
		}
	}
	return nil
}
