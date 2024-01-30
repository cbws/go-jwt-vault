# Vault token signer for jwt-go

This an extension for the jwt-go token generation library that uses the [Vault transit](https://www.vaultproject.io/docs/secrets/transit) secret engine so sign tokens.

# Example

```
package main

import (
	"context"
	"github.com/cbws/go-jwt-vault"
	"github.com/golang-jwt/jwt"
	vault "github.com/hashicorp/vault/api"
	"log"
)

func main() {
	vaultClient, err := vault.NewClient(vault.DefaultConfig())
	if err != nil {
		log.Fatalf("Could not create Vault client: %+v", err)
	}

	claims := jwt.StandardClaims{
		Subject: "test",
	}


	jwtToken := jwt.NewWithClaims(go_vault_jwt.SigningMethodVRS256, claims)

	key := go_vault_jwt.NewVaultContext(context.Background(), &go_vault_jwt.VaultConfig{
		KeyPath: "/transit",
		KeyName: "test-key",
		KeyVersion: 2,
		Client: vaultClient,
	})
	payload, err := jwtToken.SignedString(key)
	if err != nil {
		log.Fatalf("Could not create JWT token: %+v", err)
	}

	log.Printf("Token: %s", payload)
}
``` 
