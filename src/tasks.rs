use std::collections::BTreeMap;
#[cfg(feature = "server")]
use std::path::PathBuf;

use dioxus::{
    fullstack::{CborEncoding, Streaming},
    prelude::*,
};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Task {
    id: String,
    from: String,
    #[serde(default)]
    replies: BTreeMap<String, Option<TaskResult>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TaskResult {
    from: String,
    #[serde(alias = "for")]
    for_task: String,
    status: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum TaskOrResult {
    Task(Task),
    Result(TaskResult),
}


#[component]
pub fn Tasks() -> Element {
    let mut tasks = use_signal(IndexMap::new);
    let mut expanded = use_signal(|| None::<String>);
    use_hook(|| spawn(async move {
        let mut events = stream_events().await.unwrap();
        while let Some(Ok(event)) = events.next().await {
            match event {
                TaskOrResult::Task(task) => {
                    tasks.with_mut(|this| this.insert(task.id.clone(), task));
                },
                TaskOrResult::Result(result) => tasks.with_mut(|this| {
                    if let Some(task) = this.get_mut(&result.for_task) {
                        if let Some(reply) = task.replies.get_mut(&result.from) {
                            *reply = Some(result);
                        }
                    }
                }),
            }
        }
    }));
    rsx! {
        div {
            id: "status-header",
            h2 { "Tasks" }
            button { class: "", onclick: move |_| tasks.with_mut(|t| t.clear()), i { class: "fa-solid fa-trash" } }
        }
        table {
            thead { tr {
                th { "Task ID" }
                th { "From" }
                th { "To" }
            } }
            tbody {
                for task in tasks.read().values() {
                    {
                        let id = task.id.clone();
                        let is_expanded = expanded.read().as_ref() == Some(&id);
                        rsx! {
                            tr { key: "{task.id}",
                                onclick: move |_| {
                                    if is_expanded {
                                        expanded.set(None);
                                    } else {
                                        expanded.set(Some(id.clone()));
                                    }
                                },
                                td {
                                    span {
                                        style: format!("
                                            display: inline-block;
                                            transition: transform 0.3s;
                                            margin-right: 8px;
                                            transform: rotate({});
                                            user-select: none;
                                        ", if is_expanded { "90deg" } else { "0deg" }),
                                        "▶"
                                    },
                                    "{task.id}"
                                }
                                td { "{task.from}" }
                                td {
                                    style: "display: flex; gap: 1rem;",
                                    for from in task.replies.keys() {
                                        span { "{from}" }
                                    }
                                }
                            }
                            if is_expanded {
                                tr { td {
                                    colspan: "3",
                                    { render_replies(&task.replies) }
                                } }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn render_replies(replies: &BTreeMap<String, Option<TaskResult>>) -> Element {
    rsx! {
        table {
             thead {
                 tr {
                     th { "From" }
                     th { "Status" }
                 }
             }
             tbody {
                 for (from, reply) in &replies {
                     tr {
                         td { "{from}" }
                         td {
                             if let Some(reply) = reply {
                                 "{reply.status}"
                             } else {
                                 "Pending"
                             }
                         }
                    }
                }
            }
        }
    }
}

#[server]
async fn stream_events() -> Result<Streaming<TaskOrResult, CborEncoding>, ServerFnError> {
    use crate::server::CONFIG;
    let Some(log_dir) = &CONFIG.broker_log_dir else {
        return Err(ServerFnError::ServerError {
            message: "Task inspection is not enabled".into(),
            code: StatusCode::NOT_IMPLEMENTED.as_u16(),
            details: None,
        });
    };
    stream_events_helper(&log_dir)
        .await
        .map_err(ServerFnError::from)
}

#[cfg(feature = "server")]
async fn stream_events_helper(
    log_dir: &PathBuf,
) -> anyhow::Result<Streaming<TaskOrResult, CborEncoding>> {
    use std::{
        fs::{self, Metadata},
        io::SeekFrom,
        time::Duration,
    };

    use futures_util::{StreamExt, stream};
    use tokio::{
        fs::File,
        io::{AsyncBufReadExt, AsyncSeekExt, BufReader},
    };

    let Some(current_log_file) = fs::read_dir(log_dir)?
        .into_iter()
        .flatten()
        .filter(|e| e.metadata().as_ref().is_ok_and(Metadata::is_file))
        .max_by_key(|file| file.metadata().unwrap().modified().unwrap())
    else {
        warn!("No log file found yet");
        return Ok(Streaming::new(stream::empty()));
    };

    let mut file = File::open(current_log_file.path()).await?;
    info!("Opened log file: {}", current_log_file.path().display());

    let stream = async_stream::try_stream! {
        // Get current file position and size
        let mut pos = file.seek(SeekFrom::End(0)).await?;
        let mut size = file.metadata().await?.len();

        loop {
            // Check if file has grown
            let current_size = file.metadata().await?.len();
            if current_size > size {
                file.seek(SeekFrom::Start(pos)).await?;
                let reader = BufReader::new(&mut file);
                let mut lines = reader.lines();

                while let Some(line) = lines.next_line().await? {
                    if let Ok(event) = parse_line(&line) {
                        yield event;
                    }
                }

                pos = file.stream_position().await?;
                size = current_size;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };

    let stream = stream.scan((), |(), res: anyhow::Result<TaskOrResult>| async {
        match res {
            Ok(line) => Some(line),
            Err(err) => {
                warn!("Error while streaming log file {err:#}");
                None
            }
        }
    });

    Ok(Streaming::from(stream))
}

#[cfg(feature = "server")]
fn parse_line(line: &str) -> anyhow::Result<TaskOrResult> {
    let value: serde_json::Value = serde_json::from_str(line)?;
    let mut event = Deserialize::deserialize(&value["fields"])?;
    if let TaskOrResult::Task(t) = &mut event {
        let to = &value["fields"]["to"]
            .as_str()
            .expect("to field is not a string");
        t.replies = serde_json::from_str::<Vec<String>>(to)?
            .into_iter()
            .map(|s| (s, None))
            .collect();
    }

    Ok(event)
}
