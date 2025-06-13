#!/usr/bin/env just

watch:
    # Requires:
    # - `dx` CLI tool to be installed. (cargo [b]install dioxus-cli)
    # - The beam repo on branch `gen-csrs-beamdev` to be cloned at `../beam` running `./dev/beamdev demo`
    # - The mailhog server from this repos docker-compose file to be running.
    VAULT_TOKEN=$(cat ../beam/dev/pki/pki.secret) \
    BROKER_URL=http://localhost:8080 \
    VAULT_URL="http://localhost:8200" \
    CSR_DIR="../beam/dev/pki" \
    SMTP_URL="smtp://localhost:1025" \
    DB_DIR="./db" \
    BROKER_MONITORING_KEY="SuperSecretKey" \
    PKI_DEFAULT_ROLE="hd-dot-dktk-dot-com" \
    PUBLIC_BASE_URL=http://localhost:3000 \
    BROKER_ID=broker \
    dx serve --port 8000

dockerize:
    dx bundle --release
    mkdir -p ./artifacts
    cp -r target/dx/beam-cert-manager/release/web/* artifacts
    docker build -t samply/beam-cert-manager:localbuild .