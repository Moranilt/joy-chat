path "secret/data/crt/auth/public" {
  capabilities = ["read"]
}

path "secret/data/crt/mw/*" {
  capabilities = ["read", "list", "create", "update", "delete", "patch"]
}

path "secret/data/mw/*" {
  capabilities = ["read", "list", "create", "update", "delete", "patch"]
}