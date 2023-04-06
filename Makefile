AUTH_ENV = PRODUCTION=true CONSUL_HOST=localhost:8500 CONSUL_KEY_FOLDER=authentication CONSUL_KEY_VERSION=v1.0.0 CONSUL_KEY_FILE=config.yaml VAULT_SCHEME=http VAULT_HOST=localhost:8200 VAULT_TOKEN=myroot VAULT_MOUNT_PATH=secret VAULT_KEY_PUBLIC_PATH=crt/auth/public VAULT_KEY_PRIVATE_PATH=crt/auth/private VAULT_KEY_VERSION=1 GENERATE_RSA_KEYS=true PORT=8081

USERS_ENV = PRODUCTION=true AUTH_HOST=http://localhost:8081 CONSUL_HOST=localhost:8500 CONSUL_KEY_FOLDER=users CONSUL_KEY_VERSION=v1.0.0 CONSUL_KEY_FILE=config.yaml VAULT_SCHEME=http VAULT_HOST=localhost:8200 VAULT_TOKEN=users-token VAULT_MOUNT_PATH=secret VAULT_PUBLIC_KEY_PATH=crt/auth/public PORT=8082

auth-run:
	cd ./auth && go run . 

auth-production:
	cd ./auth && $(AUTH_ENV) go run .

chat-run:
	cd ./chat && go run .

users-run:
	cd ./users && go run .

users-production:
	cd ./users && $(USERS_ENV) go run .