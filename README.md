# Samply.Beam Certificate Manager

The Samply.Beam Certificate Manager is a companion service for [Samply.Beam](https://github.com/samply/beam) that automates the Public Key Infrastructure (PKI) lifecycle for a Beam network. It simplifies and secures the process of enrolling new beam proxies and ensures the continuous operation of the network by automatically renewing expiring certificates.

<img width="2542" height="430" alt="image" src="https://github.com/user-attachments/assets/9e2954de-cdd2-418b-af0c-6cc8894d5f9e" />

## Why use the Certificate Manager?

A Samply.Beam network relies on a robust PKI managed by a central [Hashicorp Vault](https://www.vaultproject.io/) instance. While Samply.Beam provides tools like `beam-enroll` to help site administrators generate keys and Certificate Signing Requests (CSRs), the process of signing these CSRs and renewing certificates can be a manual burden for the network operators.

The Certificate Manager automates this workflow by providing:
* A secure web portal for beam administrators to invite sites and manage existing ones.
* Automated validation and signing of CSRs against the central Vault PKI.
* Proactive and automatic renewal (re-signing) of certificates before they expire, preventing network disruptions.

## How It Works

The Certificate Manager operates as a central service alongside the Beam.Broker and Vault.

1.  **New Site Onboarding**:
    * A new site is invited by a beam administrators to join the network.
    * The site administrators generates a private key and a CSR for their Beam.Proxy, for example by using the `beam-enroll` tool.
    * He accesses the Certificate Manager's public web interface via the link in the email and uses the OTP to submit the CSR.
    * The Certificate Manager validates that the CSR is correctly formatted for the network (e.g., has the right Common Name).
    * It then communicates with Hashicorp Vault to sign the CSR, creating a valid certificate.

2.  **Automated Certificate Renewal**:
    * The service periodically scans all managed certificates in Vault.
    * When a certificate is nearing its expiration date, the Certificate Manager automatically requests Vault to re-sign it, extending its validity based on the configured Time-To-Live (TTL). This process is transparent to the site administrators.

## Getting Started

The Certificate Manager is designed to be run as a Docker container. It requires configuration to connect to your existing Beam.Broker, Hashicorp Vault, and an SMTP server for sending email notifications.

The [beam-deploy](https://github.com/samply/beam-deploy) repo contains an example docker compose that shows how one might run this service in production using traefik to authenticate the administrators interface. 

## Configuration

The service is configured via command-line arguments or environment variables.

| Argument | Environment Variable | Default | Description |
|---|---|---|---|
| `--vault-token-file` | `VAULT_TOKEN_FILE` | `/run/secrets/pki.secret` | File containing the token for authenticating with the Vault. |
| `--vault-url` | `VAULT_URL` | | URL of the Vault server. |
| `--broker-url` | `BROKER_URL` | | URL of the Beam Broker this manager serves. |
| `--broker-id` | `BROKER_ID` | | The BeamID of the broker, used to validate CSRs. |
| `--public-base-url`| `PUBLIC_BASE_URL` | | Public URL of this service, used in notification emails. |
| `--broker-monitoring-key` | `BROKER_MONITORING_KEY` | | API key for the Beam Broker's monitoring endpoint. |
| `--public-addr` | `PUBLIC_ADDR` | `0.0.0.0:3000` | Bind address for the public-facing web interface. |
| `--admin-addr` | `ADMIN_ADDR` | `127.0.0.1:8080` | Bind address for the administrators interface (should not be public). |
| `--pki-realm` | `PKI_REALM` | `samply_pki` | The PKI secrets engine path in Vault. |
| `--pki-default-role`| `PKI_DEFAULT_ROLE`| `samply-beam-default-role`| The Vault role used for signing certificates. |
| `--pki-eth-ttl` | `PKI_ETH_TTL` | `7d` | The new validity period for auto-renewed certificates. |
| `--smtp-url` | `SMTP_URL` | | URL of the SMTP server for sending emails. |
| `--csr-dir` | `CSR_DIR` | `/csr` | Directory to store submitted Certificate Signing Requests. |
| `--db-dir` | `DB_DIR` | | Directory to store the application's local database. |
| `--email-template` | `EMAIL_TEMPLATE` | See `DEFAULT_EMAIL_TEMPLATE` in `server.rs` | The email template used for the invitation email. The template should contain the placeholders `SITE_ID`, `URL` and `TOKEN` which will be replaced accordingly. |
| `--broker-log-dir` | `BROKER_LOG_DIR` | | Enables the task view to the tasks going through the broker in realtime. |
