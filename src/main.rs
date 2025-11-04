#[cfg(feature = "server")]
mod server;

use std::ops::Deref;

use dioxus::{
    logger::tracing::{self},
    prelude::*,
};
use jiff::{SignedDuration, Span, SpanCompare, SpanRound, ToSpan, Zoned};
use serde::{Deserialize, Serialize};

const FAVICON: Asset = asset!("/assets/favicon.ico");
const MAIN_CSS: Asset = asset!("/assets/main.css");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "server")]
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(crate::server::launch())?;
    #[cfg(not(feature = "server"))]
    dioxus::launch(App);
    Ok(())
}

#[component]
fn App() -> Element {
    rsx! {
        document::Script {
            src: "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/js/all.min.js",
            integrity: "sha512-uKQ39gEGiyUJl4AI6L+ekBdGKpGw4xJ55+xyJG7YFlJokPNYegn9KwQ3P8A7aFQAUtUsAQHep+d/lrGqrbPIDQ==",
            crossorigin: "anonymous"
        }
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: MAIN_CSS }
        Status {}
    }
}

#[component]
fn Status() -> Element {
    let mut sites_resource = use_server_future(get_status)?;
    let mut site_id = use_signal(String::new);
    let mut email = use_signal(String::new);
    rsx! {
        div { id: "status",
            div {
                id: "status-header",
                h2 { "Beam Cert Manager" }
                button { class: "", onclick: move |_| sites_resource.restart(), i { class: "fa-solid fa-arrows-rotate" } }
            }
            if let Some(Ok(sites)) = sites_resource.value().read().deref() {
                table {
                    thead { tr {
                        th { "Site ID" }
                        th { "Contact" }
                        th { "Ephemeral expiration" }
                        th { "Auto renew until" }
                        th { "Online" }
                        th { "Action" }
                    } }
                    tbody {
                        tr {
                            key: "enroll",
                            td {
                                input { r#type: "text", name: "site_id", placeholder: "Site ID", required: true, oninput: move |event| site_id.set(event.value()), value: "{site_id}" }
                            }
                            td {
                                colspan: "4",
                                input { r#type: "email", name: "email", placeholder: "Admin Email", required: true, oninput: move |event| email.set(event.value()), value: "{email}" }
                            }
                            td { class: "actions",
                                button { onclick: move |_| async move {
                                    if let Err(e) = invite_site(email.read().to_owned(), site_id.read().to_owned()).await {
                                        tracing::error!("Failed to invite site: {e:#}");
                                        return;
                                    };
                                    email.set(String::new());
                                    site_id.set(String::new());
                                    sites_resource.restart();
                                },
                                i { class: "fa-solid fa-paper-plane" } }
                            }
                        }
                        for site_info in sites {
                            tr { key: "{site_info.proxy_id}", { render_site(site_info, sites_resource) } }
                        }
                    }
                }
            }
        }
    }
}

fn render_site<T>(site: &SiteInfo, mut sites: Resource<T>) -> Element {
    let proxy_name = site.proxy_id.split_once('.').unwrap().0.to_owned();
    let proxy_id = CopyValue::new(site.proxy_id.clone());
    let email = site.email.clone();
    let now = Zoned::now();
    let span_round = SpanRound::new()
        .days_are_24_hours()
        .smallest(jiff::Unit::Hour)
        .largest(jiff::Unit::Year)
        .relative(&now);
    rsx! {
        td { "{proxy_name}" }
        td { EditableEmail { email: email.clone(), proxy_id } }
        match &site.proxy_status {
            ProxyStatus::WaitingOnCsr => rsx!{
                td { colspan: "3", "Waiting on CSR" }
                td {
                    class: "actions",
                    button { onclick: move |_| async move {
                            if let Err(e) = remove_site(proxy_id.read().to_string()).await {
                                tracing::error!("Failed to remove site: {e:#}");
                            };
                            sites.restart();
                        },
                        i { class: "fa-solid fa-trash" }
                    }
                    button { onclick: move |_| {
                        let proxy_name = proxy_name.to_owned();
                        let email = email.as_ref().unwrap().clone();
                        async move {
                            if let Err(e) = invite_site(email, proxy_name).await {
                                tracing::error!("Failed to invite site: {e:#}");
                            };
                            sites.restart();
                        } },
                        i { class: "fa-solid fa-repeat" }
                    }
                }
            },
            ProxyStatus::Registered { online, cert_expires_in, resign_until } => rsx! {
                {
                    let expires_in = cert_expires_in.round(span_round).unwrap();
                    rsx! { td { "{expires_in:#}" } }
                }
                {
                    let dt = resign_until - &now;
                    let is_short = dt.compare(SpanCompare::from(1.week()).days_are_24_hours()).unwrap().is_lt();
                    let dt_fmt = resign_until.strftime("%F");
                    rsx! { td { class: is_short.then_some("cert-warning"), "{dt_fmt:#}" } }
                }
                match online {
                    OnlineStatus::Online => rsx! {
                        td { class: "status-online",
                            i { class: "fas fa-check-circle" }
                            " Online"
                        }
                    },
                    OnlineStatus::NeverConnected => rsx!{ td { class: "status-never",
                        i { class: "fas fa-times-circle" }
                        " Offline"
                    } },
                    OnlineStatus::LastSeen(seen) => rsx! { td { class: "status-last-seen",
                        i { class: "fas fa-clock" }
                        {
                            let seen = Span::try_from(*seen).unwrap().round(SpanRound::new().days_are_24_hours().largest(jiff::Unit::Day).smallest(jiff::Unit::Minute)).unwrap();
                            rsx!(" {seen:#}")
                        }
                    } },
                }
                td {
                    class: "actions",
                    button { onclick: move |_| async move {
                            if let Err(e) = remove_site(proxy_id.read().to_string()).await {
                                tracing::error!("Failed to remove site: {e:#}");
                            };
                            sites.restart();
                        },
                        i { class: "fa-solid fa-trash" }
                    }
                    button { onclick: move |_| async move {
                        if let Err(e) = extend_validity(proxy_id.read().to_string()).await {
                            tracing::error!("Failed to extend validity: {e:#}");
                        };
                        sites.restart();
                    },
                    i { class: "fa-solid fa-plus" }
                } }
            },
        }
    }
}

#[component]
pub fn EditableEmail(email: Option<String>, proxy_id: CopyValue<String>) -> Element {
    let mut is_editing = use_signal(|| false);
    let mut email_value = use_signal(|| email.clone());
    let mut input_value = use_signal(|| email.clone().unwrap_or_default());

    let display_text = email_value()
        .as_ref()
        .filter(|e| !e.is_empty())
        .map(|e| e.as_str())
        .unwrap_or("Unknown")
        .to_owned();

    rsx! {
        if is_editing() {
            div {
                style: "display: flex; gap: 8px; justify-content: space-between; align-items: center;",
                input {
                    r#type: "email",
                    value: "{input_value}",
                    onmounted: move |el| async move {
                        el.data.set_focus(true).await.unwrap();
                    },
                    oninput: move |evt| input_value.set(evt.value().clone()),
                    style: "width: 66%",
                    autofocus: true,
                }
                div {
                    style: "display: flex; gap: 8px;",
                    button {
                        onclick: move |_| {
                            let new_email = input_value().trim().to_string();
                            if !new_email.is_empty() {
                                email_value.set(Some(new_email.clone()));
                            } else {
                                email_value.set(None);
                            }
                            is_editing.set(false);
                            async move {
                                if let Err(e) = update_email(new_email, proxy_id.read().to_owned()).await {
                                    tracing::error!("Failed to update email: {e:#}");
                                };
                            }
                        },
                        i { class: "fa-solid fa-check"}
                    }
                    button {
                        onclick: move |_| {
                            input_value.set(email_value().unwrap_or_default());
                            is_editing.set(false);
                        },
                        i { class: "fa-solid fa-xmark" }
                    }
                }
            }
        } else {
            div {
                style: "display: flex; align-items: center; gap: 8px; justify-content: space-between;",
                span {
                    style: "font-family: monospace;",
                    "{display_text}"
                }
                button {
                    onclick: move |_| {
                        input_value.set(email_value().unwrap_or_default());
                        is_editing.set(true);
                    },
                    i { class: "fa-solid fa-pencil" }
                }
            }
        }
    }
}

#[server]
async fn get_status() -> Result<Vec<SiteInfo>, ServerFnError> {
    server::get_certs()
        .await
        .inspect_err(|e| tracing::warn!(%e))
        .map_err(ServerFnError::new)
}

#[server]
async fn invite_site(email: String, site_id: String) -> Result<(), ServerFnError> {
    server::invite_site(&email, &site_id)
        .await
        .inspect_err(|e| tracing::warn!(%e))
        .map_err(ServerFnError::new)
}

#[server]
async fn remove_site(proxy_id: String) -> Result<(), ServerFnError> {
    server::remove_site(&proxy_id)
        .await
        .inspect_err(|e| tracing::warn!(%e))
        .map_err(ServerFnError::new)
}

#[server]
async fn extend_validity(proxy_id: String) -> Result<(), ServerFnError> {
    server::extend_validity(&proxy_id)
        .inspect_err(|e| tracing::warn!(%e))
        .map_err(ServerFnError::new)
}

#[server]
async fn update_email(new_email: String, proxy_id: String) -> Result<(), ServerFnError> {
    server::update_email(&proxy_id, new_email)
        .inspect_err(|e| tracing::warn!(%e))
        .map_err(ServerFnError::new)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProxyStatus {
    WaitingOnCsr,
    Registered {
        online: OnlineStatus,
        resign_until: Zoned,
        cert_expires_in: Span,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SiteInfo {
    proxy_id: String,
    email: Option<String>,
    proxy_status: ProxyStatus,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
pub enum OnlineStatus {
    Online,
    NeverConnected,
    LastSeen(SignedDuration),
}
