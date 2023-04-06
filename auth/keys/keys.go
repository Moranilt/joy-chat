package keygen

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"

	"github.com/Moranilt/joy-chat/auth/config"
	vault "github.com/hashicorp/vault/api"
)

type Keys struct {
	private  []byte
	public   []byte
	vault    *vault.Client
	vaultCfg *config.EnvVault
}

type KeysVersions struct {
	Private int
	Public  int
}

func NewKeys(v *vault.Client, env *config.EnvVault) *Keys {
	k := new(Keys)
	k.vault = v
	k.vaultCfg = env
	k.generateKeys()
	return k
}

func (k *Keys) Public() []byte {
	return k.public
}

func (k *Keys) Private() []byte {
	return k.private
}

func (k *Keys) StoreToVault() error {
	_, err := k.vault.KVv2(k.vaultCfg.MountPath).Put(
		context.Background(),
		k.vaultCfg.Key.PublicPath,
		map[string]interface{}{
			"key": string(k.public),
		},
	)
	if err != nil {
		return err
	}

	_, err = k.vault.KVv2(k.vaultCfg.MountPath).Put(
		context.Background(),
		k.vaultCfg.Key.PrivatePath,
		map[string]interface{}{
			"key": string(k.private),
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (k *Keys) generateKeys() {
	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		log.Fatal(err)
	}

	k.public = k.makePublicPEMKey(&key.PublicKey)
	k.private = k.makePrivatePEMKey(key)
}

func (k *Keys) makePrivatePEMKey(privatekey *rsa.PrivateKey) []byte {
	pemkey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privatekey),
	}

	return pem.EncodeToMemory(pemkey)
}

func (k *Keys) makePublicPEMKey(pubkey *rsa.PublicKey) []byte {
	key, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		log.Fatal(err)
	}
	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: key,
	}
	return pem.EncodeToMemory(pemkey)
}
