use std::{
    cmp::Ordering,
    collections::{HashMap, hash_map::Entry},
    future::{Future, poll_fn},
    net::SocketAddr,
    ops::Deref,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, LazyLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, anyhow, bail};
use axum::{body::Bytes, routing::get, Router};
use clap::Parser;
use dioxus::logger::tracing;
use dioxus::prelude::*;
use futures_util::{FutureExt, TryFutureExt, ready};
use jiff::{SignedDuration, Span, SpanRelativeTo, ToSpan, Unit, Zoned};
use lettre::{AsyncTransport, Message};
use rand::Rng;
use reqwest::{
    Client, Method, StatusCode, Url,
    header::{HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::Mutex};
use tokio_util::time::DelayQueue;
use x509_parser::{
    certification_request::X509CertificationRequest,
    pem::Pem,
    prelude::{FromDer, TbsCertificate, X509Certificate},
    revocation_list::CertificateRevocationList,
    x509::X509Name,
};

use crate::{OnlineStatus, ProxyStatus, SiteInfo};

#[derive(Debug, Parser)]
pub struct Config {
    #[clap(long, env)]
    vault_token: String,

    #[clap(long, env)]
    vault_url: Url,

    #[clap(long, env)]
    broker_url: Url,

    #[clap(long, env)]
    /// Beam broker id, used to verify the csr common name.
    broker_id: String,

    #[clap(long, env)]
    /// The public base URL of this service, used for generating the link in the email.
    public_base_url: Url,

    #[clap(long, env)]
    broker_monitoring_key: String,

    #[clap(long, env, default_value = "0.0.0.0:3000")]
    /// Bind addr of the public interface of this service
    public_addr: SocketAddr,

    #[clap(long, env, default_value_t = dioxus::cli_config::fullstack_address_or_localhost())]
    /// Bind addr of the admin interface of this service
    admin_addr: SocketAddr,

    #[clap(long, env, default_value = "samply_pki")]
    pki_realm: String,

    #[clap(long, env, default_value = "samply-beam-default-role")]
    pki_default_role: String,

    #[clap(long, env, default_value = "1y")]
    pki_ttl: Span,

    #[clap(long, env, default_value = "7d", value_parser=parse_eth_ttl)]
    pki_eth_ttl: Duration,

    #[clap(long, env)]
    /// Full URL to the SMTP server including auth, e.g. `smtp://user:password@localhost:587`
    smtp_url: reqwest::Url,

    #[clap(long, env, default_value = "/csr")]
    csr_dir: PathBuf,

    #[clap(long, env)]
    db_dir: PathBuf,
}

fn parse_eth_ttl(string: &str) -> anyhow::Result<Duration> {
    let span: Span = string.parse()?;
    let new_cert_ttl: Duration = span
        .to_duration(SpanRelativeTo::days_are_24_hours())?
        .try_into()?;
    anyhow::ensure!(
        new_cert_ttl > CERT_RENEW_THRESHOLD,
        "pki_eth_ttl needs to be greater than {}h",
        CERT_RENEW_THRESHOLD.as_secs() / 60 / 60
    );
    Ok(new_cert_ttl)
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
static CERTS: LazyLock<CertDb> =
    LazyLock::new(|| CertDb(sled::Db::open(&CONFIG.db_dir).expect("Failed to open db")));

struct CertDb(sled::Db);

impl CertDb {
    #[tracing::instrument(skip(self))]
    async fn get_or_create(&self, proxy_id: &str) -> anyhow::Result<DbCert> {
        if let Some(cert_info) = self.0.get(proxy_id)? {
            return Ok(serde_json::from_slice(&cert_info)?);
        }
        let email = {
            let proxy_name = proxy_id
                .split_once('.')
                .ok_or(anyhow!("Invalid proxy id"))?
                .0;
            let csr_file = CONFIG.csr_dir.join(format!("{proxy_name}.csr"));
            let csr = tokio::fs::read(&csr_file)
                .await
                .with_context(|| format!("No matching csr: {csr_file:?}"))?;
            let pem = x509_parser::pem::parse_x509_pem(&csr)?.1;
            let csr = X509CertificationRequest::from_der(&pem.contents)?.1;
            let cn = csr.certification_request_info.subject.get_cn()?;
            if cn != proxy_id {
                bail!("Csr for {proxy_id} has an invalid common name: {cn}")
            }
            csr.certification_request_info
                .subject
                .get_email()?
                .map(Into::into)
        };
        let cert = DbCert::Enrolled {
            email,
            expiration_time: &Zoned::now() + 1.year(),
            first_insert: Zoned::now(),
        };
        self.0
            .insert(proxy_id.as_bytes(), serde_json::to_vec(&cert)?);
        self.0.flush_async().await?;
        Ok(cert)
    }

    fn insert(&self, proxy_id: &str, cert: &DbCert) -> anyhow::Result<()> {
        self.0
            .insert(proxy_id.as_bytes(), serde_json::to_vec(cert)?)?;
        Ok(())
    }

    fn get_all_pending(&self) -> Vec<(String, DbCert)> {
        self.0
            .iter()
            .flatten()
            .flat_map(|(k, cert)| {
                anyhow::Ok((
                    String::from_utf8(k.to_vec())?,
                    serde_json::from_slice::<DbCert>(&cert)?,
                ))
            })
            .filter(|(_, c)| matches!(c, DbCert::Pending { .. }))
            .collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum DbCert {
    Pending {
        email: String,
        sent: Zoned,
        otp: String,
    },
    Enrolled {
        email: Option<String>,
        expiration_time: Zoned,
        first_insert: Zoned,
    },
}

impl DbCert {
    fn get_email(&self) -> Option<&str> {
        match self {
            DbCert::Pending { email, .. } => Some(&email),
            DbCert::Enrolled { email, .. } => email.as_deref(),
        }
    }
}

const CERT_RENEW_THRESHOLD: Duration = Duration::from_secs(60 * 60 * 24);

pub async fn launch() -> anyhow::Result<()> {
    dioxus::logger::initialize_default();
    // TODO: Wait for vault
    update_expiration_queue().await?;
    tokio::spawn(async move {
        loop {
            let Some(expired) = poll_fn(|cx| {
                let lock_fut = std::pin::pin!(CERT_WAIT_QUEUE.lock());
                let mut cache = ready!(lock_fut.poll(cx));
                cache.poll_expired(cx)
            })
            .await
            else {
                // No certs registered check back in 1m
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
            };
            if let Err(e) = tokio::fs::read(CONFIG.csr_dir.join(format!(
                "{}.csr",
                expired.get_ref().split_once('.').unwrap().0
            )))
            .err_into()
            .and_then(|csr| async move { sign_csr(&csr).await })
            .await
            {
                tracing::warn!("Failed to sign csr for {}: {e:#}", expired.get_ref());
            };
            if let Err(e) = update_expiration_queue().await {
                tracing::error!("Failed to update expiration queue: {e:#}");
            }
        }
    });

    let admin_listener = TcpListener::bind(CONFIG.admin_addr).await?;
    let public_listener = TcpListener::bind(CONFIG.public_addr).await?;
    tokio::try_join!(
        axum::serve(admin_listener, Router::new().serve_dioxus_application(ServeConfigBuilder::new(), crate::App)),
        axum::serve(public_listener, Router::new().route("/", get(submit::submit_csr_page).post(submit::submit_handler)))
    )?;
    Ok(())
}

async fn update_expiration_queue() -> anyhow::Result<()> {
    let (pems, crl) = tokio::try_join!(get_all_vault_pems(), get_crl())?;
    let newest_certs = get_newest_cert_per_cn(&pems, CertificateRevocationList::from_der(&crl)?.1)?;
    let mut certs_queue = CERT_WAIT_QUEUE.lock().await;
    certs_queue.clear();
    newest_certs.into_iter().for_each(|(proxy_id, cert)| {
        certs_queue.insert(
            proxy_id,
            get_ttl(&cert)
                .unwrap()
                .try_into()
                .unwrap_or(Duration::ZERO)
                .saturating_sub(CERT_RENEW_THRESHOLD),
        );
    });
    Ok(())
}

async fn get_crl() -> anyhow::Result<Bytes> {
    VAULT_CLIENT
        .get(
            CONFIG
                .vault_url
                .join(&format!("/v1/{}/crl", CONFIG.pki_realm))?,
        )
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .err_into()
        .await
}

async fn get_all_vault_pems() -> anyhow::Result<Vec<Pem>> {
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
            anyhow::Ok(x509_parser::pem::parse_x509_pem(cert.as_bytes())?.1)
        })
        .collect::<futures_util::future::TryJoinAll<_>>()
        .await
}

fn get_newest_cert_per_cn<'a>(
    pems: &'a [Pem],
    crl: CertificateRevocationList,
) -> anyhow::Result<HashMap<String, X509Certificate<'a>>> {
    let mut newest_certs = HashMap::new();
    for pem in pems.iter() {
        let cert = pem.parse_x509()?;
        let cn = cert.subject.get_cn()?.to_owned();
        if !cn.ends_with(&CONFIG.broker_id) {
            tracing::warn!("Skipping cert with CN {cn} as it does not end with the broker id {}", CONFIG.broker_id);
            continue;
        }
        if crl
            .iter_revoked_certificates()
            .any(|revoked| revoked.serial() == &cert.serial)
        {
            continue;
        }
        match newest_certs.entry(cn) {
            Entry::Occupied(mut entry)
                if get_ttl(entry.get())?
                    .compare(get_ttl(&cert)?)
                    .is_ok_and(Ordering::is_lt) =>
            {
                entry.insert(cert);
            }
            Entry::Occupied(..) => (),
            Entry::Vacant(mut empty) => {
                empty.insert(cert);
            }
        }
    }
    Ok(newest_certs)
}

pub async fn get_certs() -> anyhow::Result<Vec<SiteInfo>> {
    let (pems, crl) = tokio::try_join!(get_all_vault_pems(), get_crl())?;
    let newest_certs = get_newest_cert_per_cn(&pems, CertificateRevocationList::from_der(&crl)?.1)?;
    // Find newest cert for each proxy
    let mut status = newest_certs
        .into_iter()
        .map(|(proxy_id, cert)| {
            let err_context = format!("Failed to get cert info for {proxy_id}");
            async move {
                let db_cert = CERTS
                    .get_or_create(&proxy_id)
                    .await?;
                let expiration_time = match &db_cert {
                    DbCert::Pending { email, sent, .. } => {
                        tracing::warn!("We are waiting on a csr from {email} for {proxy_id} but it is already enrolled. Setting it up for auto resigning");
                        let expiration_time = sent + 1.year();
                        let cert = DbCert::Enrolled {
                            email: Some(email.clone()),
                            expiration_time: expiration_time.clone(),
                            first_insert: Zoned::now(),
                        };
                        CERTS.insert(&proxy_id, &cert)?;
                        expiration_time
                    }
                    DbCert::Enrolled { expiration_time, .. } => expiration_time.clone(),
                };
                let info = SiteInfo {
                    proxy_id: proxy_id.clone(),
                    email: cert.subject.get_email()?.or(db_cert.get_email()).map(Into::into),
                    proxy_status: ProxyStatus::Registered {
                        online: get_online_status(&proxy_id).await?,
                        expiration_time,
                        cert_expires_in: get_ttl(&cert)?
                    },
                };
                anyhow::Ok(info)
            }.map(|res| res.context(err_context))
        })
        .collect::<futures_util::future::JoinAll<_>>()
        .await
        .into_iter()
        .filter_map(|res| match res {
            Ok(ok) => Some(ok),
            Err(e) => {
                tracing::warn!("Failed to get proxy status: {e:#}");
                None
            }
        })
        .collect::<Vec<_>>();
    status.sort_by(|a, b| a.proxy_id.cmp(&b.proxy_id));
    status.extend(CERTS.get_all_pending().into_iter().map(|(proxy_id, cert)| {
        let DbCert::Pending { email, sent, otp } = cert else {
            unreachable!()
        };
        SiteInfo {
            proxy_id,
            email: Some(email),
            proxy_status: ProxyStatus::WaitingOnCsr,
        }
    }));
    Ok(status)
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
                Zoned::try_from(system_time)?.duration_since(&Zoned::now()),
            ))
        }
        StatusCode::NOT_FOUND => Ok(OnlineStatus::NeverConnected),
        StatusCode::OK => Ok(OnlineStatus::Online),
        s => anyhow::bail!("Unknown status getting status from {proxy_id}: {s}"),
    }
}

async fn sign_csr(csr: &[u8]) -> anyhow::Result<()> {
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
    VAULT_CLIENT
        .post(CONFIG.vault_url.join(&format!(
            "/v1/{}/sign/{}",
            CONFIG.pki_realm, CONFIG.pki_default_role
        ))?)
        .json(&serde_json::json!({
            "csr": String::from_utf8_lossy(csr),
            "common_name": cn,
            "ttl": format!("{}h", CONFIG.pki_eth_ttl.as_secs() / 60 / 60)
        }))
        .send()
        .await?
        .error_for_status()?;
    tracing::info!("Signed csr for {cn}");
    Ok(())
}

pub async fn register_new_csr(email: &str, csr: &str, expected_proxy_id: &str) -> anyhow::Result<()> {
    let pem = x509_parser::pem::parse_x509_pem(csr.as_bytes())?.1;
    let csr_info = X509CertificationRequest::from_der(&pem.contents)?.1;
    let cert_lifetime = &Zoned::now() + 1.year();
    let cn = csr_info.certification_request_info.subject.get_cn()?;
    anyhow::ensure!(
        cn == expected_proxy_id,
        "CSR was supposed to be for {expected_proxy_id} but has CN {cn}"
    );
    let proxy_name = cn.split_once('.').ok_or(anyhow!("Invalid proxy id"))?.0;
    let Ok(mut file) =
        tokio::fs::File::create_new(CONFIG.csr_dir.join(&format!("{proxy_name}.csr"))).await
    else {
        bail!("Csr for {cn} already exists");
    };
    file.write_all(csr.as_bytes()).await?;
    file.flush().await?;
    CERTS.insert(
        cn,
        &DbCert::Enrolled {
            email: Some(email.into()),
            expiration_time: &Zoned::now() + 1.year(),
            first_insert: Zoned::now(),
        },
    )?;
    sign_csr(csr.as_bytes()).await?;
    update_expiration_queue().await?;
    Ok(())
}

pub async fn remove_site(proxy_id: &str) -> anyhow::Result<()> {
    let proxy_name = proxy_id
        .split_once('.')
        .ok_or(anyhow!("Invalid proxy id"))?
        .0;
    let _ = tokio::fs::remove_file(CONFIG.csr_dir.join(&format!("{proxy_name}.csr"))).await;
    let _ = CERTS.0.remove(proxy_id.as_bytes());
    let pems = get_all_vault_pems().await?;
    for pem in pems {
        let Ok(cert) = pem.parse_x509() else {
            continue;
        };
        let Ok(cn) = cert.subject.get_cn() else {
            continue;
        };
        if cn == proxy_id {
            let serial = cert.raw_serial_as_string();
            if let Err(e) = revoke_serial(&serial).await {
                tracing::warn!("Failed to revoke cert {serial} from {proxy_id}: {e:#}");
            }
        }
    }
    update_expiration_queue().await?;
    Ok(())
}

async fn revoke_serial(serial: &str) -> anyhow::Result<()> {
    VAULT_CLIENT
        .post(
            CONFIG
                .vault_url
                .join(&format!("/v1/{}/revoke", CONFIG.pki_realm))?,
        )
        .json(&serde_json::json!({
            "serial_number": serial
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

#[tracing::instrument]
pub async fn invite_site(email: &str, site_id: &str) -> anyhow::Result<()> {
    let proxy_id = format!("{site_id}.{}", CONFIG.broker_id);
    let token: String = generate_secret::<16>();
    let user_name = CONFIG.smtp_url.username();
    let from = format!(
        "{}@{}",
        user_name.is_empty().then_some("beam").unwrap_or(user_name),
        CONFIG.smtp_url.host_str().unwrap()
    )
    .parse()?;
    let mail = Message::builder()
        .to(email.parse()?)
        .from(from)
        .body(format!(
            "You have been invited to register as bridgehead named {site_id} with the beam network.\n\
            After enrolling your bridgehead you can submit your CSR here:\n\
            {} with the following token '{token}'",
            CONFIG.public_base_url
        ))?;
    let res = EMAIL_CLIENT.send(mail).await?;
    tracing::debug!(?res);
    CERTS.insert(
        &proxy_id,
        &DbCert::Pending {
            email: email.into(),
            sent: Zoned::now(),
            otp: token.into(),
        },
    )?;
    Ok(())
}

pub trait CertExt {
    fn get_cn(&self) -> anyhow::Result<&str>;
    fn get_email(&self) -> anyhow::Result<Option<&str>>;
}

fn get_ttl(cert: &X509Certificate) -> anyhow::Result<Span> {
    let ts = jiff::Timestamp::from_second(cert.validity.not_after.timestamp())?;
    Ok(ts - jiff::Timestamp::now())
}

impl CertExt for X509Name<'_> {
    fn get_cn(&self) -> anyhow::Result<&str> {
        self.iter_common_name()
            .next()
            .ok_or(anyhow!("Cert has no CN"))?
            .as_str()
            .context("Failed to convert CN to string")
    }

    fn get_email(&self) -> anyhow::Result<Option<&str>> {
        self.iter_email()
            .next()
            .map(|mail| mail.as_str())
            .transpose()
            .context("Failed to convert email to string")
    }
}

pub fn generate_secret<const N: usize>() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789)(*&^%#@!~";
    (0..N)
        .map(|_| {
            let idx = rand::thread_rng().gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

mod submit {
    use std::borrow::Cow;

    use axum::{Form, http::Uri, response::Html};

    use super::*;

    pub async fn submit_csr_page() -> Html<&'static str> {
        Html(include_str!("../submit.html"))
    }

    #[derive(Deserialize)]
    pub struct SubmitForm {
        csr: String,
        token: String,
    }

    pub async fn submit_handler(form: Form<SubmitForm>) -> Html<Cow<'static, str>> {
        let Some((expected_proxy_id, email)) = CERTS
            .get_all_pending()
            .into_iter()
            // FIXME: constant time comparison
            .find_map(|(proxy_id, cert)| {
                matches!(cert, DbCert::Pending { ref otp, .. } if otp == &form.token)
                    .then_some((proxy_id, cert.get_email()?.to_owned()))
            })
        else {
            return Html("Invalid token or no pending registration found".into());
        };
        if let Err(e) = register_new_csr(&email, &form.csr, &expected_proxy_id).await {
            tracing::error!("Failed to register csr: {e:#?}");
            return Html(format!(
                "Failed to register csr: {e:#?}"
            ).into());
        }
        Html(format!(
            "Successfully registered csr for {expected_proxy_id} with email {email}. You can now start the bridgehead."
        ).into())	
    }
}
