package config

import (
	"strings"
)

type Config struct {
	main       *MainConfig
	mainBase64 string
}

type MainConfig struct {
	Redis RedisConfig `yaml:"redis"`
	JWT   JWTConfig   `yaml:"jwt"`
}

type RedisConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Db       int    `yaml:"db"`
	Password string `yaml:"password"`
}

type KeysConfig struct {
	Public  []byte `yaml:"public"`
	Private []byte `yaml:"private"`
}

type JWTConfig struct {
	Issuer   string   `yaml:"issuer"`
	Subject  string   `yaml:"subject"`
	Audience []string `yaml:"audience"`
	TTL      TTL      `yaml:"ttl"`
}

type TTL struct {
	Access  string `yaml:"access"`
	Refresh string `yaml:"refresh"`
}

type EnvLocal struct {
	Port            string    `yaml:"port"`
	Consul          EnvConsul `yaml:"consul"`
	Vault           EnvVault  `yaml:"vault"`
	GenerateRSAKeys bool      `yaml:"generate_rsa_keys"`
}

type EnvConsul struct {
	Host string       `yaml:"host"`
	Key  EnvConsulKey `yaml:"key"`
}

type EnvConsulKey struct {
	Folder  string `yaml:"folder"`
	Version string `yaml:"version"`
	File    string `yaml:"file"`
}

func (e *EnvConsulKey) String() string {
	chunks := []string{e.Folder, e.Version, e.File}
	return strings.Join(chunks, "/")
}

type EnvVault struct {
	Scheme    string      `yaml:"scheme"`
	Host      string      `yaml:"host"`
	Token     string      `yaml:"token"`
	MountPath string      `yaml:"mount_path"`
	Key       EnvVaultKey `yaml:"key"`
}

type EnvVaultKey struct {
	PublicPath  string `yaml:"public_path"`
	PrivatePath string `yaml:"private_path"`
	Version     int    `yaml:"version"`
}

type WatchConsulBody struct {
	Key         string
	CreateIndex int
	Flags       int
	Value       string
}
