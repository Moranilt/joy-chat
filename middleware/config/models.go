package config

type EnvConfig struct {
	Vault  VaultConfig  `yaml:"vault"`
	Consul ConsulConfig `yaml:"consul"`
	Port   string       `yaml:"port"`
}

type ConsulConfig struct {
	Host string `yaml:"host"`
	Key  string `yaml:"key"`
}

type VaultConfig struct {
	Scheme        string `yaml:"scheme"`
	Host          string `yaml:"host"`
	Token         string `yaml:"token"`
	MountPath     string `yaml:"mount_path"`
	PublicKeyPath string `yaml:"public_key_path"`
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
	Authentication  bool     `yaml:"authentication"`
	Roles           []int    `yaml:"roles"`
	HeadersRequired []string `yaml:"headers_required"`
}
