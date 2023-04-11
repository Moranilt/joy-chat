package config

type EnvConfig struct {
	Vault        VaultConfig  `yaml:"vault"`
	Consul       ConsulConfig `yaml:"consul"`
	Port         string       `yaml:"port"`
	GenerateKeys bool         `yaml:"generate_keys"`
}

type ConsulConfig struct {
	Host string `yaml:"host"`
	Key  string `yaml:"key"`
}

type VaultConfig struct {
	Scheme      string        `yaml:"scheme"`
	Host        string        `yaml:"host"`
	Token       string        `yaml:"token"`
	MountPath   string        `yaml:"mount_path"`
	Auth        VaultAuth     `yaml:"auth"`
	CrtStore    VaultCrtStore `yaml:"crt_store"`
	TokensStore string        `yaml:"tokens_store"`
}

type VaultAuth struct {
	PublicKeyPath string `yaml:"public_key_path"`
}

type VaultCrtStore struct {
	PublicKeyPath  string `yaml:"public_key_path"`
	PrivateKeyPath string `yaml:"private_key_path"`
}

type Config struct {
	Hosts []Host `yaml:"hosts"`
}

type Host struct {
	Hostname  string     `yaml:"hostname"`
	Prefix    string     `yaml:"prefix"`
	Endpoints []Endpoint `yaml:"endpoints"`
}

type Endpoint struct {
	Pattern         string   `yaml:"pattern"`
	Methods         []string `yaml:"methods"`
	MwToken         bool     `mapstructure:"mw_token"`
	Authentication  bool     `yaml:"authentication"`
	Roles           []int    `yaml:"roles"`
	HeadersRequired []string `yaml:"headers_required"`
}
