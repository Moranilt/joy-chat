auth-run:
	cd ./auth && go run . 

chat-run:
	cd ./chat && go run .

auth-production:
	cd ./auth && PRODUCTION=true CONSUL_HOST=localhost:8500 CONSUL_KEY_FOLDER=authentication CONSUL_KEY_VERSION=v1.0.0 CONSUL_KEY_FILE=config.yaml VAULT_SCHEME=http VAULT_HOST=localhost:8200 VAULT_TOKEN=myroot VAULT_MOUNT_PATH=secret VAULT_KEY_PUBLIC_PATH=crt/auth/public VAULT_KEY_PRIVATE_PATH=crt/auth/private VAULT_KEY_VERSION=1 GENERATE_RSA_KEYS=true PORT=8081 go run .