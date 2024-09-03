package main

import (
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

type Config struct {
	Concurrency    int    `mapstructure:"Concurrency"`
	DomainNameFile string `mapstructure:"DomainNameFile"`
	HTTPTimeout    int    `mapstructure:"HTTPTimeout"`
	LogLevel       zerolog.Level
	Logger         zerolog.Logger
}

func initConfig() *Config {
	viper.AutomaticEnv()
	viper.SetEnvPrefix("DNS_CHECK")

	viper.SetDefault("Concurrency", 20)
	viper.SetDefault("DomainNameFile", "domains.txt")
	viper.SetDefault("HTTPTimeout", 5)

	var configuration Config

	err := viper.Unmarshal(&configuration)

	if err != nil {
		panic(err)
	}

	// Log Level switch
	switch strings.ToLower(viper.GetString("LogLevel")) {
	case "debug":
		configuration.LogLevel = zerolog.DebugLevel
	case "info":
		configuration.LogLevel = zerolog.InfoLevel
	case "warn":
		configuration.LogLevel = zerolog.WarnLevel
	case "error":
		configuration.LogLevel = zerolog.ErrorLevel
	case "fatal":
		configuration.LogLevel = zerolog.FatalLevel
	case "panic":
		configuration.LogLevel = zerolog.PanicLevel
	default:
		configuration.LogLevel = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(configuration.LogLevel)

	// Create multiple output steams for zerolog
	multi := zerolog.MultiLevelWriter(zerolog.ConsoleWriter{Out: os.Stderr})

	logger := zerolog.New(multi).With().Timestamp().Logger()

	configuration.Logger = logger

	return &configuration
}
