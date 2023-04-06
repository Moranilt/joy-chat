package config

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"os"

	vault "github.com/hashicorp/vault/api"
	"github.com/spf13/viper"
	_ "github.com/spf13/viper/remote"
	"gopkg.in/yaml.v3"
)

const (
	ENV_PORT                   = "PORT"
	ENV_CONSUL_HOST            = "CONSUL_HOST"
	ENV_CONSUL_KEY_FOLDER      = "CONSUL_KEY_FOLDER"
	ENV_CONSUL_KEY_VERSION     = "CONSUL_KEY_VERSION"
	ENV_CONSUL_KEY_FILE        = "CONSUL_KEY_FILE"
	ENV_VAULT_SCHEME           = "VAULT_SCHEME"
	ENV_VAULT_HOST             = "VAULT_HOST"
	ENV_VAULT_TOKEN            = "VAULT_TOKEN"
	ENV_VAULT_MOUNT_PATH       = "VAULT_MOUNT_PATH"
	ENV_VAULT_KEY_PUBLIC_PATH  = "VAULT_KEY_PUBLIC_PATH"
	ENV_VAULT_KEY_PRIVATE_PATH = "VAULT_KEY_PRIVATE_PATH"
	ENV_VAULT_KEY_VERSION      = "VAULT_KEY_VERSION"
	ENV_GENERATE_RSA_KEYS      = "GENERATE_RSA_KEYS"
)

type ConsulWatcher interface {
	WatchConsul(env *EnvConsul, newConfigs []WatchConsulBody) error
}

type Configurator interface {
	ConsulWatcher
	ReadConfig(env *EnvConsul) error
	Redis() *RedisConfig
	JWT() *JWTConfig
	ReadVaultKeys(vaultClient *vault.Client, env *EnvVault) (*KeysConfig, error)
}

// TODO: replace with ReadConfig instead NewConfig and config.ReadConfig
func NewConfig() Configurator {
	return &Config{
		main: &MainConfig{},
	}
}

func (c *Config) Redis() *RedisConfig {
	return &c.main.Redis
}

func (c *Config) JWT() *JWTConfig {
	return &c.main.JWT
}

func (c *Config) readConsul(env *EnvConsul) error {
	viper.AddRemoteProvider("consul", env.Host, env.Key.String())
	viper.SetConfigType("yaml")
	err := viper.ReadRemoteConfig()
	if err != nil {
		return err
	}

	err = viper.Unmarshal(c.main)
	if err != nil {
		return err
	}

	err = validateStringTime(c.main.JWT.TTL.Access)
	if err != nil {
		return fmt.Errorf("access TTL: %w", err)
	}

	err = validateStringTime(c.main.JWT.TTL.Refresh)
	if err != nil {
		return fmt.Errorf("refresh TTL: %w", err)
	}
	return nil
}

func (c *Config) WatchConsul(env *EnvConsul, newConfigs []WatchConsulBody) error {
	var consulConfig *WatchConsulBody
	for _, nc := range newConfigs {
		if nc.Key == env.Key.String() {
			consulConfig = &nc
			break
		}
	}
	if consulConfig == nil {
		return nil
	}

	if consulConfig.Value == c.mainBase64 {
		return nil
	} else {
		c.mainBase64 = consulConfig.Value
	}

	base64Decoded, err := base64.StdEncoding.DecodeString(consulConfig.Value)
	if err != nil {
		return err
	}

	log.Printf("New settings: \n%s\n", string(base64Decoded))

	err = yaml.Unmarshal(base64Decoded, c.main)
	if err != nil {
		return err
	}

	return nil
}

func (c *Config) ReadVaultKeys(vaultClient *vault.Client, env *EnvVault) (*KeysConfig, error) {
	kv := vaultClient.KVv2(env.MountPath)
	publicCert, err := kv.GetVersion(
		context.Background(),
		env.Key.PublicPath,
		env.Key.Version,
	)
	if err != nil {
		return nil, err
	}

	privateCert, err := kv.GetVersion(
		context.Background(),
		env.Key.PrivatePath,
		env.Key.Version,
	)
	if err != nil {
		return nil, err
	}

	publicKey, ok := publicCert.Data["key"].(string)
	if !ok {
		return nil, fmt.Errorf("not valid type of public key")
	}

	privateKey, ok := privateCert.Data["key"].(string)
	if !ok {
		return nil, fmt.Errorf("not valid type of private key")
	}

	return &KeysConfig{
		Public:  []byte(publicKey),
		Private: []byte(privateKey),
	}, nil
}

func (c *Config) ReadConfig(env *EnvConsul) error {
	err := c.readConsul(env)
	if err != nil {
		return err
	}

	return nil
}

func NewVaultClient(env *EnvVault) (*vault.Client, error) {
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

func ReadEnv() (*EnvLocal, error) {
	var envCfg EnvLocal
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
		envCfg = EnvLocal{
			Consul: EnvConsul{
				Host: viper.GetString(ENV_CONSUL_HOST),
				Key: EnvConsulKey{
					Folder:  viper.GetString(ENV_CONSUL_KEY_FOLDER),
					Version: viper.GetString(ENV_CONSUL_KEY_VERSION),
					File:    viper.GetString(ENV_CONSUL_KEY_FILE),
				},
			},
			Vault: EnvVault{
				Scheme:    viper.GetString(ENV_VAULT_SCHEME),
				Host:      viper.GetString(ENV_VAULT_HOST),
				Token:     viper.GetString(ENV_VAULT_TOKEN),
				MountPath: viper.GetString(ENV_VAULT_MOUNT_PATH),
				Key: EnvVaultKey{
					PublicPath:  viper.GetString(ENV_VAULT_KEY_PUBLIC_PATH),
					PrivatePath: viper.GetString(ENV_VAULT_KEY_PRIVATE_PATH),
					Version:     viper.GetInt(ENV_VAULT_KEY_VERSION),
				},
			},
			GenerateRSAKeys: viper.GetBool(ENV_GENERATE_RSA_KEYS),
			Port:            viper.GetString(ENV_PORT),
		}
	}

	return &envCfg, nil
}
