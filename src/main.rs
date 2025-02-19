#[cfg(feature = "server")]
mod server;

use std::{
    ops::Deref,
    sync::LazyLock,
    time::{Duration, SystemTime},
};

use dioxus::{logger::tracing::warn, prelude::*};
use jiff::{SignedDuration, Span, SpanRound};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[layout(Navbar)]
    #[route("/")]
    Home {},
    #[route("/blog/:id")]
    Blog { id: i32 },
}

const FAVICON: Asset = asset!("/assets/favicon.ico");
const MAIN_CSS: Asset = asset!("/assets/main.css");

fn main() {
    #[cfg(feature = "server")]
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(crate::server::launch());
    #[cfg(not(feature = "server"))]
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: MAIN_CSS }
        Router::<Route> {}
    }
}

/// Home page
#[component]
fn Home() -> Element {
    rsx! {
        Status {}
    }
}

/// Blog page
#[component]
pub fn Blog(id: i32) -> Element {
    rsx! {
        div {
            id: "blog",

            // Content
            h1 { "This is blog #{id}!" }
            p { "In blog #{id}, we show how the Dioxus router works and how URL parameters can be passed as props to our route components." }

            // Navigation links
            Link {
                to: Route::Blog { id: id - 1 },
                "Previous"
            }
            span { " <---> " }
            Link {
                to: Route::Blog { id: id + 1 },
                "Next"
            }
        }
    }
}

/// Shared navbar component.
#[component]
fn Navbar() -> Element {
    rsx! {
        div {
            id: "navbar",
            Link {
                to: Route::Home {},
                "Home"
            }
            Link {
                to: Route::Blog { id: 1 },
                "Blog"
            }
        }

        Outlet::<Route> {}
    }
}

/// Echo component that demonstrates fullstack server functions.
#[component]
fn Status() -> Element {
    let mut response = use_server_future(get_status)?;
    rsx! {
        script { src: "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/js/all.min.js" }
        div { id: "status",
            if let Some(Ok(thing)) = response.value().read().deref() {
                table {
                    thead { tr {
                        th { "Proxy ID" }
                        th { "Email" }
                        th { "Status" }
                        th { "Expires in" }
                        th { "Action" }
                    } }
                    tbody {
                        for proxy_status in thing {
                            { render_proxy_status(proxy_status) }
                        }
                    }
                }
                button { onclick: move |_| response.restart(), "Refresh" }
            }
        }
    }
}

fn render_proxy_status(status: &ProxyStatus) -> Element {
    let (ProxyStatus::Registered { proxy_id, .. } | ProxyStatus::WaitingOnCsr { proxy_id, .. }) = status;
    let proxy_name = proxy_id.split_once('.').unwrap().0;
    let email = match status {
        ProxyStatus::WaitingOnCsr { email, ..} => email.as_str(),
        ProxyStatus::Registered { email, .. } => email.as_deref().unwrap_or("Unknown"),
    };
    rsx!{
        tr { key: proxy_id,
            td { "{proxy_name}" }
            td { "{email}" }
            match status {
                ProxyStatus::WaitingOnCsr { .. } => rsx!{ td { colspan: "3", "Waiting on CSR" } },
                ProxyStatus::Registered { proxy_id, email, online, cert_expires_in } => rsx! {
                    match online {
                        OnlineStatus::Online => rsx! {
                            td { class: "status-online",
                                i { class: "fas fa-check-circle" }
                                "Online"
                            }
                        },
                        OnlineStatus::NeverConnected => rsx!{ td { class: "status-never",
                            i { class: "fas fa-times-circle" }
                            "Never"
                        } },
                        OnlineStatus::LastSeen(seen) => rsx! { td { class: "status-last-seen",
                            i { class: "fas fa-clock" }
                            {
                                let seen = Span::try_from(*seen).unwrap().round(SpanRound::new().days_are_24_hours().largest(jiff::Unit::Day).smallest(jiff::Unit::Minute)).unwrap();
                                rsx!("Last seen {seen:#}")
                            }
                        } },
                    }
                    {
                        let expires_in_hours = cert_expires_in.as_hours();
                        let expires_in_days = expires_in_hours / 24;
                        if expires_in_days == 0 {
                            rsx! { td { class: "cert-warning", "{expires_in_hours} hours" } }
                        } else {
                            rsx! { td { class: (expires_in_days < 5).then_some("cert-warning"),"{expires_in_days} days" } }
                        }
                    }
                },
            }
            td { "Todo" }
        }
    }
}

/// Echo the user input on the server.
#[server]
async fn get_status() -> Result<Vec<ProxyStatus>, ServerFnError> {
    server::get_certs().await.inspect_err(|e| warn!(%e)).map_err(ServerFnError::new)
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ProxyStatus {
    WaitingOnCsr { proxy_id: String, email: String },
    Registered {
        proxy_id: String,
        email: Option<String>,
        online: OnlineStatus,
        cert_expires_in: SignedDuration,
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
pub enum OnlineStatus {
    Online,
    NeverConnected,
    LastSeen(SignedDuration),
}
