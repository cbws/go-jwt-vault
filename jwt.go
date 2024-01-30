package go_vault_jwt

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	vault "github.com/hashicorp/vault/api"
)

var (
	SigningMethodVRS256 *SigningMethodVaultTransit
	SigningMethodVRS384 *SigningMethodVaultTransit
	SigningMethodVRS512 *SigningMethodVaultTransit

	// ErrMissingConfig is returned when Sign or Verify did not find a configuration in the provided context
	ErrMissingConfig = errors.New("go_vault_jwt: missing configuration in provided context")
)

type VaultConfig struct {
	KeyPath    string
	KeyName    string
	KeyVersion int
	Client     *vault.Client
}

type vaultConfigKey struct{}

// NewVaultContext returns a new context.Context that carries a provided VaultConfig value
func NewVaultContext(parent context.Context, val *VaultConfig) context.Context {
	return context.WithValue(parent, vaultConfigKey{}, val)
}

// VaultFromContext extracts a VaultConfig from a context.Context
func VaultFromContext(ctx context.Context) (*VaultConfig, bool) {
	val, ok := ctx.Value(vaultConfigKey{}).(*VaultConfig)
	return val, ok
}

func init() {
	// RS256
	SigningMethodVRS256 = &SigningMethodVaultTransit{
		"VRS256",
		jwt.SigningMethodRS256,
		crypto.SHA256,
	}
	jwt.RegisterSigningMethod(SigningMethodVRS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodVRS256
	})
	// RS384
	SigningMethodVRS384 = &SigningMethodVaultTransit{
		"VRS384",
		jwt.SigningMethodRS384,
		crypto.SHA384,
	}
	jwt.RegisterSigningMethod(SigningMethodVRS384.Alg(), func() jwt.SigningMethod {
		return SigningMethodVRS384
	})
	// RS512
	SigningMethodVRS512 = &SigningMethodVaultTransit{
		"VRS512",
		jwt.SigningMethodRS512,
		crypto.SHA512,
	}
	jwt.RegisterSigningMethod(SigningMethodVRS512.Alg(), func() jwt.SigningMethod {
		return SigningMethodVRS512
	})
}

type SigningMethodVaultTransit struct {
	alg      string
	override jwt.SigningMethod
	hasher   crypto.Hash
}

func (s SigningMethodVaultTransit) Sign(signingString string, key interface{}) ([]byte, error) {
	var ctx context.Context

	// check to make sure the key is a context.Context
	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return nil, jwt.ErrInvalidKey
	}

	config, ok := VaultFromContext(ctx)
	if !ok {
		return nil, ErrMissingConfig
	}

	if !s.hasher.Available() {
		return nil, jwt.ErrHashUnavailable
	}

	digest := s.hasher.New()
	_, err := digest.Write([]byte(signingString))
	if err != nil {
		return nil, err
	}

	var hashType string
	switch s.hasher {
	case crypto.SHA256:
		hashType = "sha2-256"
	case crypto.SHA384:
		hashType = "sha2-384"
	case crypto.SHA512:
		hashType = "sha2-512"
	default:
		return nil, fmt.Errorf("unknown hasher %T", s.hasher)
	}

	_, signature, err := signVault(*config, config.Client, hashType, digest.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("could not sign using Vault: %+v", err)
	}

	return signature, nil
}

func (s SigningMethodVaultTransit) Verify(signingString string, signature []byte, key interface{}) error {
	var ctx context.Context

	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return jwt.ErrInvalidKey
	}

	config, ok := VaultFromContext(ctx)
	if !ok {
		return ErrMissingConfig
	}

	digest := s.hasher.New()
	_, err := digest.Write([]byte(signingString))
	if err != nil {
		return err
	}

	var hashType string
	switch s.hasher {
	case crypto.SHA256:
		hashType = "sha2-256"
	case crypto.SHA384:
		hashType = "sha2-384"
	case crypto.SHA512:
		hashType = "sha2-512"
	default:
		return fmt.Errorf("unknown hasher %T", s.hasher)
	}

	valid, err := verifyVault(*config, config.Client, hashType, signature, digest.Sum(nil))
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func (s SigningMethodVaultTransit) Alg() string {
	return s.alg
}

func (s SigningMethodVaultTransit) Override() {
	s.alg = s.override.Alg()
	jwt.RegisterSigningMethod(s.alg, func() jwt.SigningMethod {
		return s
	})
}

func (s *SigningMethodVaultTransit) Hash() crypto.Hash {
	return s.hasher
}
