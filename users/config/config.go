package config

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	vault "github.com/hashicorp/vault/api"
	"github.com/spf13/viper"
	_ "github.com/spf13/viper/remote"
	"gopkg.in/yaml.v3"
)

const (
	ENV_PORT                  = "PORT"
	ENV_CONSUL_HOST           = "CONSUL_HOST"
	ENV_CONSUL_KEY_FOLDER     = "CONSUL_KEY_FOLDER"
	ENV_CONSUL_KEY_VERSION    = "CONSUL_KEY_VERSION"
	ENV_CONSUL_KEY_FILE       = "CONSUL_KEY_FILE"
	ENV_VAULT_SCHEME          = "VAULT_SCHEME"
	ENV_VAULT_HOST            = "VAULT_HOST"
	ENV_VAULT_TOKEN           = "VAULT_TOKEN"
	ENV_VAULT_MOUNT_PATH      = "VAULT_MOUNT_PATH"
	ENV_VAULT_PUBLIC_KEY_PATH = "VAULT_PUBLIC_KEY_PATH"
	ENV_AUTH_HOST             = "AUTH_HOST"
)

type EnvConfig struct {
	Vault    VaultConfig  `yaml:"vault"`
	Consul   ConsulConfig `yaml:"consul"`
	AuthHost string       `yaml:"auth_host"`
	Port     string       `yaml:"port"`
}

type VaultConfig struct {
	Scheme        string `yaml:"scheme"`
	Host          string `yaml:"host"`
	Token         string `yaml:"token"`
	MountPath     string `yaml:"mount_path"`
	PublicKeyPath string `yaml:"public_key_path"`
}

type ConsulConfig struct {
	Host string          `yaml:"host"`
	Key  ConsulConfigKey `yaml:"key"`
}

type ConsulConfigKey struct {
	Folder  string `yaml:"folder"`
	Version string `yaml:"version"`
	File    string `yaml:"file"`
}

func (cc *ConsulConfigKey) String() string {
	return strings.Join([]string{cc.Folder, cc.Version, cc.File}, "/")
}

type Config struct {
	DB DBConfig `yaml:"db"`
}

type DBConfig struct {
	Port     int    `yaml:"port"`
	Host     string `yaml:"host"`
	Password string `yaml:"password"`
	User     string `yaml:"user"`
	Sslmode  string `yaml:"sslmode"`
	DBName   string `yaml:"dbname"`
}

// TODO: make function to read ENV variables

func ReadConfig(name string, dest any) error {
	cfgBytes, err := os.ReadFile(name)
	if err != nil {
		return nil
	}

	err = yaml.Unmarshal(cfgBytes, dest)
	if err != nil {
		return nil
	}

	return nil
}

func ReadConsulConfig(env *ConsulConfig, dest any) error {
	err := viper.AddRemoteProvider("consul", env.Host, env.Key.String())
	if err != nil {
		return err
	}

	viper.SetConfigType("yaml")
	err = viper.ReadRemoteConfig()
	if err != nil {
		return err
	}

	err = viper.Unmarshal(&dest)
	if err != nil {
		return err
	}

	return nil
}

func NewVaultClient(env *VaultConfig) (*vault.Client, error) {
	vaultHost := url.URL{
		Scheme: env.Scheme,
		Host:   env.Host,
	}

	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = vaultHost.String()
	client, err := vault.NewClient(vaultCfg)
	if err != nil {
		return nil, err
	}
	client.SetToken(env.Token)

	return client, nil
}

func VaultPublicKey(vc *vault.Client, env *VaultConfig) ([]byte, error) {
	kv := vc.KVv2(env.MountPath)
	publicCert, err := kv.Get(
		context.Background(),
		env.PublicKeyPath,
	)
	if err != nil {
		return nil, err
	}

	publicKey, ok := publicCert.Data["key"].(string)
	if !ok {
		return nil, fmt.Errorf("not valid type of public key")
	}

	return []byte(publicKey), nil
}

func ReadEnv() (*EnvConfig, error) {
	var envCfg EnvConfig
	viper.AutomaticEnv()
	isProduction := viper.GetBool("PRODUCTION")

	if !isProduction {
		bytes, err := os.ReadFile("./env_example.yml")
		if err != nil {
			return nil, err
		}

		err = yaml.Unmarshal(bytes, &envCfg)
		if err != nil {
			return nil, err
		}
	} else {
		log.Println("Production mode!")
		envCfg = EnvConfig{
			Consul: ConsulConfig{
				Host: viper.GetString(ENV_CONSUL_HOST),
				Key: ConsulConfigKey{
					Folder:  viper.GetString(ENV_CONSUL_KEY_FOLDER),
					Version: viper.GetString(ENV_CONSUL_KEY_VERSION),
					File:    viper.GetString(ENV_CONSUL_KEY_FILE),
				},
			},
			Vault: VaultConfig{
				Scheme:        viper.GetString(ENV_VAULT_SCHEME),
				Host:          viper.GetString(ENV_VAULT_HOST),
				Token:         viper.GetString(ENV_VAULT_TOKEN),
				MountPath:     viper.GetString(ENV_VAULT_MOUNT_PATH),
				PublicKeyPath: viper.GetString(ENV_VAULT_PUBLIC_KEY_PATH),
			},
			Port:     viper.GetString(ENV_PORT),
			AuthHost: viper.GetString(ENV_AUTH_HOST),
		}
	}

	return &envCfg, nil
}
