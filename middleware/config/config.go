package config

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"

	vault "github.com/hashicorp/vault/api"
	"github.com/spf13/viper"
	_ "github.com/spf13/viper/remote"
	"gopkg.in/yaml.v2"
)

const (
	ENV_PORT                  = "PORT"
	ENV_CONSUL_HOST           = "CONSUL_HOST"
	ENV_CONSUL_KEY            = "CONSUL_KEY"
	ENV_VAULT_SCHEME          = "VAULT_SCHEME"
	ENV_VAULT_HOST            = "VAULT_HOST"
	ENV_VAULT_TOKEN           = "VAULT_TOKEN"
	ENV_VAULT_MOUNT_PATH      = "VAULT_MOUNT_PATH"
	ENV_VAULT_PUBLIC_KEY_PATH = "VAULT_PUBLIC_KEY_PATH"
)

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
				Key:  viper.GetString(ENV_CONSUL_KEY),
			},
			Vault: VaultConfig{
				Scheme:        viper.GetString(ENV_VAULT_SCHEME),
				Host:          viper.GetString(ENV_VAULT_HOST),
				Token:         viper.GetString(ENV_VAULT_TOKEN),
				MountPath:     viper.GetString(ENV_VAULT_MOUNT_PATH),
				PublicKeyPath: viper.GetString(ENV_VAULT_PUBLIC_KEY_PATH),
			},
			Port: viper.GetString(ENV_PORT),
		}
	}

	return &envCfg, nil
}

func ReadConsulConfig(env *ConsulConfig) (*Config, error) {
	err := viper.AddRemoteProvider("consul", env.Host, env.Key)
	if err != nil {
		return nil, err
	}

	viper.SetConfigType("yaml")
	err = viper.ReadRemoteConfig()
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = viper.Unmarshal(&cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
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
