package config

import (
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	Workers     int    `mapstructure:"workers"`
	MaxFileSize string `mapstructure:"max-file-size"`
	NoColor     bool   `mapstructure:"no-color"`
	Debug       bool   `mapstructure:"debug"`
}

func Default() Config {
	return Config{
		Workers:     10,
		MaxFileSize: "5M",
		NoColor:     false,
		Debug:       false,
	}
}

func Load(configPath string) (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("json")

	home, err := os.UserHomeDir()
	if err == nil {
		v.AddConfigPath(filepath.Join(home, ".config", "syck"))
		v.AddConfigPath(filepath.Join(home, ".syckrc"))
	}

	v.AddConfigPath(".")
	v.AddConfigPath(".syckrc.json")
	v.AddConfigPath(".syckrc")

	if configPath != "" {
		v.SetConfigFile(configPath)
	}

	v.SetDefault("workers", 10)
	v.SetDefault("max-file-size", "5M")
	v.SetDefault("no-color", false)
	v.SetDefault("debug", false)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return v, err
		}
	}

	return v, nil
}
