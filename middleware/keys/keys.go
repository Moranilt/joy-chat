package keys

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"

	"github.com/Moranilt/joy-chat/middleware/config"
	vault "github.com/hashicorp/vault/api"
)

const (
	DEFAULT_BIT_SIZE = 2048
)

type Keys struct {
	privateKey *rsa.PrivateKey
	randReader io.Reader
	vault      *vault.Client
	vaultCfg   *config.VaultConfig
}

func NewKeys(vc *vault.Client, vCfg *config.VaultConfig) *Keys {
	k := new(Keys)
	k.vault = vc
	k.vaultCfg = vCfg
	k.randReader = rand.Reader
	return k
}

func (k *Keys) Sign(signMsg string) string {
	hashed := sha256.Sum256([]byte(signMsg))
	sig, err := rsa.SignPKCS1v15(k.randReader, k.privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		log.Fatal(err)
	}
	return base64.RawStdEncoding.EncodeToString(sig)
}

func (k *Keys) Validate(sig string, signMsg string) error {
	encBase64, err := base64.RawStdEncoding.DecodeString(sig)
	if err != nil {
		return err
	}
	hashed := sha256.Sum256([]byte(signMsg))
	return rsa.VerifyPKCS1v15(&k.privateKey.PublicKey, crypto.SHA256, hashed[:], encBase64)
}

func (k *Keys) GetFromVault() error {
	privateCert, err := k.vault.KVv2(k.vaultCfg.MountPath).Get(
		context.Background(),
		k.vaultCfg.CrtStore.PrivateKeyPath,
	)
	if err != nil {
		return err
	}

	privateKey, ok := privateCert.Data["key"].(string)
	if !ok {
		return fmt.Errorf("not valid type of private key")
	}

	pemBlock, _ := pem.Decode([]byte(privateKey))
	parsedPrivate, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return err
	}

	k.privateKey = parsedPrivate
	return nil
}

func (k *Keys) StoreToVault() error {
	if k.privateKey == nil {
		return fmt.Errorf("you should read or generate you private key first")
	}

	public := k.makePublicPEMKey(&k.privateKey.PublicKey)
	private := k.makePrivatePEMKey(k.privateKey)

	_, err := k.vault.KVv2(k.vaultCfg.MountPath).Put(
		context.Background(),
		k.vaultCfg.CrtStore.PublicKeyPath,
		map[string]interface{}{
			"key": string(public),
		},
	)
	if err != nil {
		return err
	}

	_, err = k.vault.KVv2(k.vaultCfg.MountPath).Put(
		context.Background(),
		k.vaultCfg.CrtStore.PrivateKeyPath,
		map[string]interface{}{
			"key": string(private),
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (k *Keys) GenerateKeys(bitSize int) error {
	key, err := rsa.GenerateKey(k.randReader, bitSize)
	if err != nil {
		return err
	}

	k.privateKey = key
	return nil
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
