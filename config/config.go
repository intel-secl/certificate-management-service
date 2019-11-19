/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"errors"
	"intel/isecl/cms/constants"
	"os"
	"path"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	clog "intel/isecl/lib/common/log"
)
var log = clog.GetDefaultLogger()

// should move this into lib common, as its duplicated across TDS and TDA

// Configuration is the global configuration struct that is marshalled/unmarshaled to a persisted yaml file
// Probably should embed a config generic struct
type Configuration struct {
	configFile       string
	Port             int
	LogLevel         logrus.Level
	AuthServiceUrl         string

	CACertValidity         int
	Organization           string
	Locality               string
	Province               string
	Country                string
	KeyAlgorithm           string
	KeyAlgorithmLength     int
	RootCACertDigest       string
	TlsCertDigest          string
	TokenDurationMins      int

	ReadTimeout            time.Duration
	ReadHeaderTimeout      time.Duration
	WriteTimeout           time.Duration
	IdleTimeout            time.Duration
	MaxHeaderBytes         int

	AasJwtCn               string
	AasTlsCn               string
	AasTlsSan              string

	AuthDefender struct {
		MaxAttempts         int
		IntervalMins        int
		LockoutDurationMins int
	}
}

var mu sync.Mutex

var global *Configuration

func Global() *Configuration {
	log.Trace("config/config:Global() Entering")
	defer log.Trace("config/config:Global() Leaving")
	
	if global == nil {
		global = Load(path.Join(constants.ConfigDir, constants.ConfigFile))
	}
	return global
}

var ErrNoConfigFile = errors.New("no config file")

func (c *Configuration) Save() error {
	log.Trace("config/config:Save() Entering")
	defer log.Trace("config/config:Save() Leaving")

	if c.configFile == "" {
		return ErrNoConfigFile
	}
	file, err := os.OpenFile(c.configFile, os.O_RDWR, 0)
	if err != nil {
		// we have an error
		if os.IsNotExist(err) {
			// error is that the config doesnt yet exist, create it
			file, err = os.Create(c.configFile)
			os.Chmod(c.configFile, 0440)
			if err != nil {
				return err
			}
		} else {
			// someother I/O related error
			return err
		}
	}
	defer file.Close()
	return yaml.NewEncoder(file).Encode(c)
}

func Load(path string) *Configuration {
	log.Trace("config/config:Load() Entering")
	defer log.Trace("config/config:Load() Leaving")

	var c Configuration
	file, err := os.Open(path)
	if err == nil {
		defer file.Close()
		yaml.NewDecoder(file).Decode(&c)
	} else {
		// file doesnt exist, create a new blank one
		c.LogLevel = logrus.InfoLevel
	}

	c.configFile = path
	return &c
}
