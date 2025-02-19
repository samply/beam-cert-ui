use std::{
    future::poll_fn,
    net::SocketAddr,
    ops::Deref,
    path::PathBuf,
    str::FromStr,
    sync::LazyLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context};
use clap::Parser;
use dioxus::logger::tracing;
use dioxus::prelude::*;
use futures_util::{ready, FutureExt};
use jiff::{SignedDuration, Span, Timestamp, Unit};
use reqwest::{
    header::{HeaderName, HeaderValue},
    Client, Method, StatusCode, Url,
};
use serde::Deserialize;
use serde_json::Value;
use tokio::{net::TcpListener, sync::Mutex};
use tokio_util::time::DelayQueue;
use x509_parser::{
    certification_request::X509CertificationRequest,
    prelude::{FromDer, TbsCertificate, X509Certificate},
};

use crate::{OnlineStatus, ProxyStatus};

#[derive(Debug, Parser)]
pub struct Config {
    #[clap(long, env)]
    vault_token: String,

    #[clap(long, env)]
    vault_url: Url,

    #[clap(long, env)]
    broker_url: Url,

    #[clap(long, env)]
    broker_monitoring_key: String,

    #[clap(long, env, default_value = "samply_pki")]
    pki_realm: String,

    #[clap(long, env, default_value = "samply-beam-default-role")]
    pki_default_role: String,

    #[clap(long, env, default_value = "1y")]
    pki_ttl: Span,

    #[clap(long, env, default_value = "7d")]
    pki_eth_ttl: Span,

    #[clap(long, env)]
    smtp_url: reqwest::Url,

    #[clap(long, env, default_value = "/csr")]
    csr_dir: PathBuf,

    #[clap(long, env)]
    db_dir: PathBuf,
}

static CONFIG: LazyLock<Config> = LazyLock::new(Config::parse);
static VAULT_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .default_headers(
            [(
                HeaderName::from_static("x-vault-token"),
                HeaderValue::from_str(&CONFIG.vault_token).unwrap(),
            )]
            .into_iter()
            .collect(),
        )
        .build()
        .unwrap()
});
static CERT_WAIT_QUEUE: LazyLock<Mutex<DelayQueue<String>>> = LazyLock::new(|| Default::default());

pub async fn launch() {
    dioxus::logger::initialize_default();

    let router = axum::Router::new()
        .serve_dioxus_application(ServeConfigBuilder::new(), crate::App)
        .into_make_service();

    tokio::spawn(async {
        loop {
            let Some(expired) = poll_fn(|cx| {
                let cache = ready!(CERT_WAIT_QUEUE.lock().poll(cx));
                cache.poll_expired(cx)
            })
            .await
            else {
                // No certs registered check back in 1m
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
            };
            let csr = match tokio::fs::read(CONFIG.csr_dir.join(format!("{}.csr", expired.get_ref()))).await {
                Ok(csr) => csr,
                Err(e) => {
                    tracing::warn!("Failed to read csr for {}: {e}", expired.get_ref());
                    continue;
                }
            };
            if let Err(e) = sign_csr(&csr, &CONFIG.pki_eth_ttl).await {
                tracing::warn!("Failed to sign csr for {}: {e}", expired.get_ref());
            };
        }
    });

    let listener = TcpListener::bind(dioxus::cli_config::fullstack_address_or_localhost())
        .await
        .unwrap();
    axum::serve(listener, router).await.unwrap();
}

pub async fn get_certs() -> anyhow::Result<Vec<ProxyStatus>> {
    let mut res: serde_json::Value = VAULT_CLIENT
        .request(
            Method::from_bytes(b"LIST").unwrap(),
            CONFIG
                .vault_url
                .join(&format!("/v1/{}/certs", CONFIG.pki_realm))
                .unwrap(),
        )
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let serials: Vec<String> = Deserialize::deserialize(&res["data"]["keys"])?;
    serials
        .into_iter()
        .map(|s| async move {
            let value = VAULT_CLIENT
                .get(
                    CONFIG
                        .vault_url
                        .join(&format!("/v1/{}/cert/{s}", CONFIG.pki_realm))
                        .unwrap(),
                )
                .send()
                .await?
                .error_for_status()?
                .json::<Value>()
                .await?;
            let cert: String = Deserialize::deserialize(&value["data"]["certificate"])?;
            let pem = x509_parser::pem::parse_x509_pem(cert.as_bytes())?.1;
            let cert = pem.parse_x509()?.to_owned();
            let cn = cert.get_cn()?;
            anyhow::Ok(ProxyStatus::Registered {
                proxy_id: cn.to_owned(),
                email: cert.get_email()?.map(ToOwned::to_owned),
                online: get_online_status(cn).await?,
                cert_expires_in: cert.get_ttl()?,
            })
        })
        .collect::<futures_util::future::TryJoinAll<_>>()
        .await
}

static BROKER_CLIENT: LazyLock<Client> = LazyLock::new(Client::new);

async fn get_online_status(proxy_id: &str) -> anyhow::Result<OnlineStatus> {
    let res = BROKER_CLIENT
        .get(
            CONFIG
                .broker_url
                .join(&format!("/v1/health/proxies/{proxy_id}"))
                .unwrap(),
        )
        .basic_auth("", Some(&CONFIG.broker_monitoring_key))
        .send()
        .await?;
    match res.status() {
        StatusCode::SERVICE_UNAVAILABLE => {
            let system_time: SystemTime = Deserialize::deserialize(
                &res.json::<serde_json::Value>().await?["last_disconnect"],
            )?;
            Ok(OnlineStatus::LastSeen(
                Timestamp::try_from(system_time)?.duration_since(Timestamp::now()),
            ))
        }
        StatusCode::NOT_FOUND => Ok(OnlineStatus::NeverConnected),
        StatusCode::OK => Ok(OnlineStatus::Online),
        s => anyhow::bail!("Unknown status getting status from {proxy_id}: {s}"),
    }
}

async fn sign_csr(csr: &[u8], ttl: &Span) -> anyhow::Result<()> {
    let pem = x509_parser::pem::parse_x509_pem(csr)?.1;
    let csr_info = X509CertificationRequest::from_der(&pem.contents)?.1;
    let cn = csr_info
        .certification_request_info
        .subject
        .iter_common_name()
        .next()
        .ok_or(anyhow!("Cert has no CN"))?
        .as_str()
        .context("Failed to convert CN to string")?;
    if !cn.starts_with(CONFIG.broker_url.host_str().unwrap()) {
        anyhow::bail!("Cert has an invalid hostname")
    }
    VAULT_CLIENT
        .post(CONFIG.vault_url.join(&format!(
            "/v1/{}/sign/{}",
            CONFIG.pki_realm, CONFIG.pki_default_role
        ))?)
        .json(&serde_json::json!({
            "csr": csr,
            "common_name": cn,
            "ttl": ttl.total(Unit::Hour)?
        }))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

static EMAIL_CLIENT: LazyLock<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>> =
    LazyLock::new(|| {
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::from_url(&CONFIG.smtp_url.to_string())
            .expect("Failed to build email client")
            .build()
    });

pub trait CertExt {
    fn get_ttl(&self) -> anyhow::Result<SignedDuration>;
    fn get_cn(&self) -> anyhow::Result<&str>;
    fn get_email(&self) -> anyhow::Result<Option<&str>>;
}

impl CertExt for X509Certificate<'_> {
    fn get_ttl(&self) -> anyhow::Result<SignedDuration> {
        let ts = jiff::Timestamp::from_second(self.validity.not_after.timestamp())?;
        Ok(ts.duration_since(jiff::Timestamp::now()))
    }

    fn get_cn(&self) -> anyhow::Result<&str> {
        self.subject
            .iter_common_name()
            .next()
            .ok_or(anyhow!("Cert has no CN"))?
            .as_str()
            .context("Failed to convert CN to string")
    }

    fn get_email(&self) -> anyhow::Result<Option<&str>> {
        self.subject
            .iter_email()
            .next()
            .map(|mail| mail.as_str())
            .transpose()
            .context("Failed to convert email to string")
    }
}
