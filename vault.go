package go_vault_jwt

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

func signVault(ctx context.Context, config VaultConfig, vault *vault.Client, hash string, hashed []byte) (int, []byte, error) {
	response, err := vault.Logical().WriteWithContext(ctx, fmt.Sprintf("%s/sign/%s", config.KeyPath, config.KeyName), map[string]interface{}{
		"key_version":          config.KeyVersion,
		"input":                base64.StdEncoding.EncodeToString(hashed),
		"prehashed":            true,
		"signature_algorithm":  "pkcs1v15",
		"marshaling_algorithm": "jws",
		"hash_algorithm":       hash,
	})
	if err != nil {
		return 0, nil, err
	}

	parts := strings.Split(response.Data["signature"].(string), ":")
	keyVersion, err := strconv.Atoi(string([]rune(parts[1])[1:]))
	if err != nil {
		return 0, nil, fmt.Errorf("could not parse key version: %+v", err)
	}

	bla, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, nil, err
	}

	return keyVersion, bla, nil
}

func verifyVault(ctx context.Context, config VaultConfig, vault *vault.Client, hash string, signature, signingString []byte) (bool, error) {
	requestData := map[string]interface{}{
		"input":                base64.StdEncoding.EncodeToString(signingString),
		"prehashed":            true,
		"signature":            fmt.Sprintf("vault:v%d:%s", config.KeyVersion, base64.RawURLEncoding.EncodeToString(signature)),
		"signature_algorithm":  "pkcs1v15",
		"marshaling_algorithm": "jws",
		"hash_algorithm":       hash,
	}
	response, err := vault.Logical().WriteWithContext(ctx, fmt.Sprintf("%s/verify/%s", config.KeyPath, config.KeyName), requestData)
	if err != nil {
		return false, err
	}

	valid, ok := response.Data["valid"].(bool)
	if !ok {
		return false, errors.New("unexpected response from Vault")
	}

	return valid, nil
}
