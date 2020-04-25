# Vault token signer for jwt-go

This an extension for the jwt-go token generation library that uses the [Vault transit](https://www.vaultproject.io/docs/secrets/transit) secret engine so sign tokens.

# Example

```
claims := jwt.StandardClaims{
    Subject: "test",
}

jwtToken := jwt.NewWithClaims(go_vault_jwt.SigningMethodVRS256, claims)

config := &go_vault_jwt.VaultConfig{
    KeyPath: "/transit",
    KeyName: "test-key",
    KeyVersion: 2,
    Client: vaultClient,
}

key := go_vault_jwt.NewVaultContext(context.Background(), config)
payload, err := jwtToken.SignedString(key)
``` 
