//! Connect-RPC serving over the local Unix socket.
//!
//! Unary methods (GetState, Discover, Pair, ListDevices, Revoke) use the plain
//! Connect unary framing: the whole request/response body is one encoded
//! message. HostMetrics, Logs and ControlService are server-streaming and use
//! Connect's enveloped framing: each message is a 5-byte prefix (1 flag byte +
//! 4-byte big-endian length) then the payload, and the stream is closed by an
//! end-of-stream envelope (flag 0x02, JSON trailer).
//!
//! This module owns the WIRE only. Management (`control`) and discovery live in
//! their own modules; routing here stays a table of paths.
//!
//! Both wire codecs Connect defines are supported: protobuf-binary (default)
//! and JSON (debuggable — `curl --unix-socket … -H 'content-type:
//! application/json'` for unary, `application/connect+json` for streaming).

use std::convert::Infallible;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::{Request, Response, StatusCode};
use prost::Message;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc::Sender;

use crate::install::execute as install;
use crate::state::Store;
use crate::util::now_millis;
use crate::vpn_clients;
use crate::ddns;
use crate::mesh;
use crate::{
    backup, container_backup, container_backup_run, container_removal, container_update, container_schedule, containers, control, discover, dkim, history, lockdown, mailbox,
    metrics, models, mods, pb, restore, security,
    uninstall, update,
};

/// One body type for both unary (a single `Full`) and streaming (a channel-fed
/// `ChannelBody`) responses, so `route` can return either.
pub type Resp = Response<BoxBody<Bytes, Infallible>>;

const METRICS_DEFAULT_INTERVAL: u64 = 2;
const METRICS_MAX_INTERVAL: u64 = 60;
const LOGS_DEFAULT_TAIL: u32 = 200;
const LOGS_MAX_TAIL: u32 = 5000;

/// Never fails at the hyper layer: every error becomes a Connect error response.
pub async fn serve(req: Request<Incoming>, store: Arc<Mutex<Store>>) -> Result<Resp, Infallible> {
    Ok(route(req, store).await.unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    }))
}

async fn route(req: Request<Incoming>, store: Arc<Mutex<Store>>) -> anyhow::Result<Resp> {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let codec = Codec::from_content_type(parts.headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()));
    let bytes = body.collect().await?.to_bytes();

    // Who is calling, and is this server still willing to answer them. Runs
    // before the body is looked at, so an expired device gets the same answer
    // from every verb instead of one refusal per implementation.
    if let Some(refusal) = session_refusal(&parts, &path, &store)? {
        return Ok(refusal);
    }

    match path.as_str() {
        "/gryonixnexusd.v1.Control/GetState" => {
            let _req: pb::GetStateRequest = codec.decode(&bytes)?;
            let state = store.lock().unwrap().snapshot()?;
            codec.encode(&state)
        }
        "/gryonixnexusd.v1.Control/Discover" => {
            let _req: pb::DiscoverRequest = codec.decode(&bytes)?;
            let result = discover::scan().await?;
            // Persist what adoption found so GetState reflects it afterwards.
            store.lock().unwrap().record_discovery(&result.services)?;
            codec.encode(&result)
        }
        // The whole host, not only the catalog. Read-only, unary: two docker
        // reads with no state to change.
        "/gryonixnexusd.v1.Containers/ListContainers" => {
            let _req: pb::ListContainersRequest = codec.decode(&bytes)?;
            let names = store.lock().unwrap().container_names()?;
            let inventory = containers::inventory(&names).await?;
            codec.encode(&inventory)
        }
        // Rename one group, then answer with the WHOLE inventory rather than
        // the one row that changed: the client re-reads the list after every
        // write anyway (the same rule the dashboard follows for status), and a
        // reply that carried only the edited row would let a stale list stand
        // beside a fresh name.
        "/gryonixnexusd.v1.Containers/SetContainerGroupName" => {
            let req: pb::SetContainerGroupNameRequest = codec.decode(&bytes)?;
            let name = match containers::sanitise_name(&req.display_name) {
                Ok(name) => name,
                Err(why) => {
                    return Ok(connect_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_argument",
                        &why,
                    ))
                }
            };
            let existing = store.lock().unwrap().container_names()?;
            let inventory = containers::inventory(&existing).await?;
            // The gate: a key the host does not currently report is refused
            // rather than stored. The name table is the agent's own state, and
            // a client must not be able to grow it with strings that name
            // nothing on this machine.
            let Some(group) = containers::resolve(&inventory, &req.key) else {
                return Ok(connect_error(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "this host reports no container group with that key",
                ));
            };
            // Write the HOST's string, never the caller's — the same reason
            // `discover::known_service_id` returns the table's constant.
            let key = group.key.clone();
            store.lock().unwrap().set_container_name(&key, &name)?;
            let names = store.lock().unwrap().container_names()?;
            let refreshed = containers::inventory(&names).await?;
            codec.encode(&refreshed)
        }
        // Start / stop / restart one group. Server-streaming, so it decodes the
        // enveloped request form like every other stream.
        "/gryonixnexusd.v1.Containers/ControlContainerGroup" => {
            let req: pb::ControlContainerGroupRequest = codec.decode_enveloped(&bytes)?;
            let names = store.lock().unwrap().container_names()?;
            Ok(containers::control_group(codec, req, names).await)
        }
        // Same tail machinery as Control/Logs, a different resolver: a
        // host-reported group key instead of a catalog id.
        "/gryonixnexusd.v1.Containers/ContainerGroupLogs" => {
            let req: pb::ContainerGroupLogsRequest = codec.decode_enveloped(&bytes)?;
            let names = store.lock().unwrap().container_names()?;
            match containers::containers_of_group(&req.key, &names).await {
                // A refusal happens BEFORE the stream opens, so it is a plain
                // error response — there is nothing to trail.
                Err(refusal) => Ok(refusal.response()),
                Ok((label, list)) => Ok(tail_all(codec, list, label, req.tail)),
            }
        }
        "/gryonixnexusd.v1.Containers/InspectContainer" => {
            let req: pb::InspectContainerRequest = codec.decode(&bytes)?;
            let names = store.lock().unwrap().container_names()?;
            Ok(containers::inspect(codec, req, &names).await)
        }
        // What a backup of this group would take. Detection unless the owner
        // has corrected it — and the reply says which of the two it is.
        "/gryonixnexusd.v1.Containers/GetContainerBackupPlan" => {
            let req: pb::GetContainerBackupPlanRequest = codec.decode(&bytes)?;
            let names = store.lock().unwrap().container_names()?;
            match containers::details_of_group(&req.key, &names).await {
                Err(refusal) => Ok(refusal.response()),
                Ok((group, details)) => {
                    let stored = store.lock().unwrap().container_backup_plan(&group.key)?;
                    let plan = container_backup::effective(&group.key, &details, stored);
                    codec.encode(&plan)
                }
            }
        }
        "/gryonixnexusd.v1.Containers/SetContainerBackupPlan" => {
            let req: pb::SetContainerBackupPlanRequest = codec.decode(&bytes)?;
            let names = store.lock().unwrap().container_names()?;
            // The key is gated BEFORE anything is written, exactly as the
            // rename verb gates it: the plan table is the agent's own state.
            match containers::details_of_group(&req.key, &names).await {
                Err(refusal) => Ok(refusal.response()),
                Ok((group, details)) => {
                    // `Some` with an empty plan means "back up nothing"; absent
                    // means "forget my correction". They are different
                    // instructions and only PRESENCE tells them apart.
                    let sanitised = match req.plan {
                        Some(plan) => match container_backup::sanitise(plan, &group, &details) {
                            Ok(plan) => Some(plan),
                            Err(why) => {
                                return Ok(connect_error(
                                    StatusCode::BAD_REQUEST,
                                    "invalid_argument",
                                    &why,
                                ))
                            }
                        },
                        None => None,
                    };
                    store
                        .lock()
                        .unwrap()
                        .set_container_backup_plan(&group.key, sanitised.as_ref())?;
                    let stored = store.lock().unwrap().container_backup_plan(&group.key)?;
                    let plan = container_backup::effective(&group.key, &details, stored);
                    codec.encode(&plan)
                }
            }
        }
        // Run the plan. The stored correction is read HERE and handed down, so
        // the executor never reaches for the store while a stream is open.
        "/gryonixnexusd.v1.Containers/RunContainerGroupBackup" => {
            let req: pb::RunContainerGroupBackupRequest = codec.decode_enveloped(&bytes)?;
            let names = store.lock().unwrap().container_names()?;
            let stored = store.lock().unwrap().container_backup_plan(&req.key)?;
            Ok(container_backup_run::run(codec, req, names, stored).await)
        }
        // What removal would delete, before anything is deleted.
        "/gryonixnexusd.v1.Containers/PreviewContainerGroupRemoval" => {
            let req: pb::PreviewContainerGroupRemovalRequest = codec.decode(&bytes)?;
            let names = store.lock().unwrap().container_names()?;
            Ok(container_removal::preview(codec, req, &names).await)
        }
        "/gryonixnexusd.v1.Containers/RemoveContainerGroup" => {
            let req: pb::RemoveContainerGroupRequest = codec.decode_enveloped(&bytes)?;
            let names = store.lock().unwrap().container_names()?;
            // **A removed group must not carry its last backup time forward.**
            // The row outlives the group, so a stack torn down and brought back
            // under the same compose name reads as "backed up an hour ago" —
            // pointing at an archive this very removal deleted — and then waits
            // a whole window before its first real one. Measured on
            // `vps-middle`, 2026-08-25. Done here rather than inside the
            // stream: the store is the API layer's to touch, exactly as the
            // name and plan reads above it are.
            store
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .forget_container_backup_run(&req.key)?;
            Ok(container_removal::remove(codec, req, names).await)
        }
        "/gryonixnexusd.v1.Containers/UpdateContainerGroup" => {
            let req: pb::UpdateContainerGroupRequest = codec.decode_enveloped(&bytes)?;
            let names = store.lock().unwrap().container_names()?;
            let stored = store.lock().unwrap().container_backup_plan(&req.key)?;
            Ok(container_update::run(codec, req, names, stored).await)
        }
        "/gryonixnexusd.v1.Containers/GetContainerBackupSchedule" => {
            let req: pb::GetContainerBackupScheduleRequest = codec.decode(&bytes)?;
            let names = store.lock().unwrap().container_names()?;
            // Gated on the key BEFORE anything is read back, exactly as the
            // rename and the plan are: the schedule table is agent state, and a
            // key the host does not report must not be able to create a row.
            match containers::details_of_group(&req.key, &names).await {
                Err(refusal) => Ok(refusal.response()),
                Ok((group, _)) => codec.encode(&container_schedule::schedule_of(&store, &group.key)),
            }
        }
        "/gryonixnexusd.v1.Containers/ListContainerGroupBackups" => {
            let req: pb::ListContainerGroupBackupsRequest = codec.decode(&bytes)?;
            let names = store.lock().unwrap().container_names()?;
            // Gated on the key BEFORE the directory is touched, exactly as the
            // schedule and the plan are: the path is built from the key, and a
            // key the host does not report must not be able to name one.
            match containers::details_of_group(&req.key, &names).await {
                Err(refusal) => Ok(refusal.response()),
                Ok((group, _)) => match container_backup_run::list(&group.key) {
                    Ok(list) => codec.encode(&list),
                    Err(refusal) => Ok(refusal),
                },
            }
        }
        "/gryonixnexusd.v1.Containers/SetContainerBackupSchedule" => {
            let req: pb::SetContainerBackupScheduleRequest = codec.decode(&bytes)?;
            let names = store.lock().unwrap().container_names()?;
            if !req.schedule.is_empty() && !container_schedule::is_valid(&req.schedule) {
                return Ok(connect_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_argument",
                    "schedule must be daily, weekly or monthly, or empty to switch it off",
                ));
            }
            match containers::details_of_group(&req.key, &names).await {
                Err(refusal) => Ok(refusal.response()),
                Ok((group, _)) => {
                    store.lock().unwrap().set_container_backup_schedule(&group.key, &req.schedule)?;
                    codec.encode(&container_schedule::schedule_of(&store, &group.key))
                }
            }
        }
        "/gryonixnexusd.v1.Pairing/Pair" => {
            let req: pb::PairRequest = codec.decode(&bytes)?;
            // The out-of-band code proves the operator: the SSH tunnel already
            // authenticated the device, but only someone with server access
            // could read the code `gryonixnexusd pair-code` printed. Fail closed —
            // no valid code, no enrollment.
            let device = {
                let store = store.lock().unwrap();
                if !store.consume_pairing_code(&req.code)? {
                    return Ok(connect_error(
                        StatusCode::UNAUTHORIZED,
                        "permission_denied",
                        "invalid or expired pairing code",
                    ));
                }
                store.pair(&req.device_public_key, &req.label, &req.device_uid)?
            };
            codec.encode(&pb::PairResponse { device: Some(device) })
        }
        "/gryonixnexusd.v1.Pairing/ListDevices" => {
            let _req: pb::ListDevicesRequest = codec.decode(&bytes)?;
            let devices = store.lock().unwrap().list_devices()?;
            codec.encode(&pb::DeviceList { devices })
        }
        "/gryonixnexusd.v1.Pairing/Revoke" => {
            let req: pb::RevokeRequest = codec.decode(&bytes)?;
            let revoked = store.lock().unwrap().revoke(&req.device_id)?;
            codec.encode(&pb::RevokeResponse { revoked })
        }
        "/gryonixnexusd.v1.Pairing/GetSessionPolicy" => {
            let _req: pb::GetSessionPolicyRequest = codec.decode(&bytes)?;
            let policy = lock(&store).session_policy()?;
            codec.encode(&policy)
        }
        "/gryonixnexusd.v1.Pairing/SetSessionPolicy" => {
            let req: pb::SetSessionPolicyRequest = codec.decode(&bytes)?;
            // An unoffered window is `invalid_argument`, not a rounded number:
            // a client that asks for two months has a bug, and silently giving
            // it three would sign devices out on a date nobody chose.
            match lock(&store).set_session_policy(req.auto_logout_months) {
                Ok(policy) => codec.encode(&policy),
                Err(err) => Ok(connect_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_argument",
                    &err.to_string(),
                )),
            }
        }
        "/gryonixnexusd.v1.Vault/GetVault" => {
            let _req: pb::GetVaultRequest = codec.decode(&bytes)?;
            let snapshot = lock(&store).vault_snapshot()?;
            codec.encode(&snapshot)
        }
        "/gryonixnexusd.v1.Vault/PutVaultEntries" => {
            let req: pb::PutVaultEntriesRequest = codec.decode(&bytes)?;
            match lock(&store).put_vault_entries(&req.entries) {
                Ok(snapshot) => {
                    reconcile_service_secrets(&snapshot);
                    codec.encode(&snapshot)
                }
                Err(err) => Ok(connect_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_argument",
                    &err.to_string(),
                )),
            }
        }
        "/gryonixnexusd.v1.Vault/DeleteVaultEntry" => {
            let req: pb::DeleteVaultEntryRequest = codec.decode(&bytes)?;
            let snapshot = lock(&store).delete_vault_entry(&req.id, &req.device_uid)?;
            reconcile_service_secrets(&snapshot);
            codec.encode(&snapshot)
        }
        "/gryonixnexusd.v1.Control/ServiceStatus" => {
            let req: pb::ServiceStatusRequest = codec.decode(&bytes)?;
            Ok(control::service_status(codec, req).await)
        }
        // Management (Phase 2). Server-streaming, so it decodes the enveloped
        // request form like the other streams.
        "/gryonixnexusd.v1.Control/ControlService" => {
            let req: pb::ControlServiceRequest = codec.decode_enveloped(&bytes)?;
            Ok(control::control_service(codec, req, store).await)
        }
        // Read-only history, unary: the collector's buckets are bounded files,
        // so there is nothing to stream and the call stays under the gate.
        "/gryonixnexusd.v1.Control/MetricsHistory" => {
            let req: pb::MetricsHistoryRequest = codec.decode(&bytes)?;
            Ok(history::metrics_history(codec, req))
        }
        // Backups. Three unary reads/bookkeeping calls plus one stream: a run
        // takes minutes to hours and has to report progress, while listing,
        // estimating and deleting are bounded and belong under the channel gate
        // with the other short calls. All four go through the deployment's own
        // root-owned wrapper — the agent owns the contract, not the engine.
        "/gryonixnexusd.v1.Backup/ListBackups" => {
            let req: pb::ListBackupsRequest = codec.decode(&bytes)?;
            Ok(backup::list_backups(codec, req))
        }
        "/gryonixnexusd.v1.Backup/EstimateBackup" => {
            let req: pb::EstimateBackupRequest = codec.decode(&bytes)?;
            Ok(backup::estimate_backup(codec, req).await)
        }
        "/gryonixnexusd.v1.Backup/DeleteBackup" => {
            let req: pb::DeleteBackupRequest = codec.decode(&bytes)?;
            Ok(backup::delete_backup(codec, req).await)
        }
        "/gryonixnexusd.v1.Backup/RunBackup" => {
            let req: pb::RunBackupRequest = codec.decode_enveloped(&bytes)?;
            Ok(backup::run_backup(codec, req).await)
        }
        "/gryonixnexusd.v1.Backup/GetBackupSchedule" => {
            let req: pb::GetBackupScheduleRequest = codec.decode(&bytes)?;
            Ok(backup::get_backup_schedule(codec, req).await)
        }
        "/gryonixnexusd.v1.Backup/SetBackupSchedule" => {
            let req: pb::SetBackupScheduleRequest = codec.decode(&bytes)?;
            Ok(backup::set_backup_schedule(codec, req).await)
        }
        // Updates. Same division as backups, decided by the same question: is
        // there partial state to watch? A check and the schedule are bounded
        // and answer at once; a run is a backup plus a pull plus a health wait
        // and can end in a rollback, so it streams.
        "/gryonixnexusd.v1.Update/CheckUpdates" => {
            let req: pb::CheckUpdatesRequest = codec.decode(&bytes)?;
            Ok(update::check_updates(codec, req).await)
        }
        "/gryonixnexusd.v1.Update/GetUpdatePolicy" => {
            let req: pb::GetUpdatePolicyRequest = codec.decode(&bytes)?;
            Ok(update::get_update_policy(codec, req).await)
        }
        "/gryonixnexusd.v1.Update/SetUpdateSchedule" => {
            let req: pb::SetUpdateScheduleRequest = codec.decode(&bytes)?;
            Ok(update::set_update_schedule(codec, req).await)
        }
        "/gryonixnexusd.v1.Update/RunUpdate" => {
            let req: pb::RunUpdateRequest = codec.decode_enveloped(&bytes)?;
            Ok(update::run_update(codec, req).await)
        }
        // The admin-guard toggle. Deployment-scoped like Update, and both RPCs
        // are unary: status/on/off/only are fast local operations (nftables +
        // Caddy reload), not container engine calls, so there is no partial
        // state worth streaming. See lockdown.rs.
        "/gryonixnexusd.v1.Lockdown/GetLockdown" => {
            let req: pb::GetLockdownRequest = codec.decode(&bytes)?;
            Ok(lockdown::get_lockdown(codec, req).await)
        }
        "/gryonixnexusd.v1.Lockdown/SetLockdown" => {
            let req: pb::SetLockdownRequest = codec.decode(&bytes)?;
            Ok(lockdown::set_lockdown(codec, req).await)
        }
        // Read-only status of CrowdSec and its nftables bouncer. Unary and
        // deployment-scoped like Lockdown: every field is one fast local
        // `cscli` call, and a host without CrowdSec answers `present = false`
        // rather than an error. Installs nothing — see security.rs.
        "/gryonixnexusd.v1.Security/GetSecurityStatus" => {
            let req: pb::GetSecurityStatusRequest = codec.decode(&bytes)?;
            Ok(security::get_security_status(codec, req).await)
        }
        // The one pair on this service that touches the host: whether sshd
        // still takes passwords, and the switch for it. Unary like Lockdown's,
        // and for the same reason — a drop-in, an `sshd -t` and a reload have
        // no partial state worth streaming. The policy lives in
        // `install::ssh_password`; these only carry it. See security.rs.
        "/gryonixnexusd.v1.Security/GetSshPasswordState" => {
            let req: pb::GetSshPasswordStateRequest = codec.decode(&bytes)?;
            Ok(security::get_ssh_password_state(codec, req).await)
        }
        // The one verb here that runs CrowdSec itself — start, stop, restart,
        // update, install, remove. Server-streaming like `ControlService`, so
        // it decodes the enveloped request form. See security.rs.
        "/gryonixnexusd.v1.Security/ControlSecurity" => {
            let req: pb::ControlSecurityRequest = codec.decode_enveloped(&bytes)?;
            Ok(security::control_security(codec, req).await)
        }
        // Who the defence is blocking, and who it will never block. Unary and
        // fast like the status: `cscli decisions list` plus, for the allowlist,
        // one `cscli allowlists` call whose failure is the agent's own test of
        // whether this CrowdSec has the command at all. The mutating pair
        // answers with the list RE-READ from the host. See security.rs.
        "/gryonixnexusd.v1.Security/GetSecurityDecisions" => {
            let req: pb::GetSecurityDecisionsRequest = codec.decode(&bytes)?;
            Ok(security::get_security_decisions(codec, req).await)
        }
        "/gryonixnexusd.v1.Security/SetSecurityDecision" => {
            let req: pb::SetSecurityDecisionRequest = codec.decode(&bytes)?;
            Ok(security::set_security_decision(codec, req).await)
        }
        "/gryonixnexusd.v1.Security/GetSecurityAllowlist" => {
            let req: pb::GetSecurityAllowlistRequest = codec.decode(&bytes)?;
            Ok(security::get_security_allowlist(codec, req).await)
        }
        "/gryonixnexusd.v1.Security/SetSecurityAllowlist" => {
            let req: pb::SetSecurityAllowlistRequest = codec.decode(&bytes)?;
            Ok(security::set_security_allowlist(codec, req).await)
        }
        "/gryonixnexusd.v1.Security/SetSshPasswordLogin" => {
            let req: pb::SetSshPasswordLoginRequest = codec.decode(&bytes)?;
            Ok(security::set_ssh_password_login(codec, req).await)
        }
        // Removing one service. There is no route for the wrapper's `--all`,
        // and that absence is the design: the full erase removes this agent, so
        // the stream describing it would be killed by it. See uninstall.rs.
        "/gryonixnexusd.v1.Uninstall/RemoveService" => {
            let req: pb::RemoveServiceRequest = codec.decode_enveloped(&bytes)?;
            Ok(uninstall::remove_service(codec, req, store).await)
        }
        // Restoring one service. Streaming, same shape as RemoveService: a
        // restore can run for minutes and has to report progress, and the
        // wrapper it drives is the one gate on which archive paths may be
        // read. See restore.rs for why there is no per-flavour routing
        // exception here the way Backup has one.
        "/gryonixnexusd.v1.Restore/RunRestore" => {
            let req: pb::RunRestoreRequest = codec.decode_enveloped(&bytes)?;
            Ok(restore::run_restore(codec, req).await)
        }
        // Installing a service from nothing (Ф4 срез 4.2). Streaming, same
        // shape as RunRestore/RunUpdate/RunBackup: an install runs for
        // minutes and reports progress; the two-channel error rule is the
        // same as every other destructive streamed verb here. See
        // install::execute's module doc for the id gate that decides
        // `invalid_argument` (unknown catalog id) vs `failed_precondition`
        // (real id, no executor for it yet in this build).
        "/gryonixnexusd.v1.Install/InstallService" => {
            let req: pb::InstallServiceRequest = codec.decode_enveloped(&bytes)?;
            Ok(install::run_install(codec, req, store).await)
        }
        // Unary, and deliberately reachable without installing anything: the
        // relay of scenario B carries no services at all, so nothing there
        // would ever regenerate its wrappers, and a host whose last service
        // was removed keeps wrappers that dispatch on it.
        // Reattaching to a run that outlived the client that started it. See
        // `install::journal` for why the run was never owned by the stream, and
        // `run_watch_install` for why replay and follow are one verb.
        "/gryonixnexusd.v1.Install/WatchInstall" => {
            let req: pb::WatchInstallRequest = codec.decode_enveloped(&bytes)?;
            Ok(install::run_watch_install(codec, req, store).await)
        }
        // Every long operation, not just installs — see the `Jobs` service in
        // the schema, and `jobs` for the journal both verbs read.
        "/gryonixnexusd.v1.Jobs/WatchJob" => {
            let req: pb::WatchJobRequest = codec.decode_enveloped(&bytes)?;
            Ok(crate::jobs::run_watch_job(codec, req).await)
        }
        "/gryonixnexusd.v1.Jobs/ListJobs" => {
            let req: pb::ListJobsRequest = codec.decode(&bytes)?;
            Ok(crate::jobs::run_list_jobs(codec, req).await)
        }
        "/gryonixnexusd.v1.Jobs/CancelJob" => {
            let req: pb::CancelJobRequest = codec.decode(&bytes)?;
            Ok(crate::jobs::run_cancel_job(codec, req).await)
        }
        "/gryonixnexusd.v1.Install/ProvisionHost" => {
            let req: pb::ProvisionHostRequest = codec.decode(&bytes)?;
            Ok(install::run_provision_host(codec, req).await)
        }
        // VPN client devices. All four unary, all four driven through the
        // PANEL's own API — the engine (and, crucially, the lock that keeps two
        // writers from handing one address to two clients) stays there. See
        // `vpn_clients`' module doc.
        // The mesh's control plane. All five unary and all five driven
        // through the `headscale` CLI in its container — the engine stays
        // where it is, this carries the contract. See `mesh`' module doc for
        // why nothing here echoes the engine's raw JSON.
        "/gryonixnexusd.v1.Mesh/ListMeshUsers" => {
            let req: pb::ListMeshUsersRequest = codec.decode(&bytes)?;
            Ok(mesh::list_users(codec, req).await)
        }
        "/gryonixnexusd.v1.Mesh/CreateMeshUser" => {
            let req: pb::CreateMeshUserRequest = codec.decode(&bytes)?;
            Ok(mesh::create_user(codec, req).await)
        }
        "/gryonixnexusd.v1.Mesh/CreateMeshAuthKey" => {
            let req: pb::CreateMeshAuthKeyRequest = codec.decode(&bytes)?;
            Ok(mesh::create_auth_key(codec, req).await)
        }
        "/gryonixnexusd.v1.Mesh/ListMeshNodes" => {
            let req: pb::ListMeshNodesRequest = codec.decode(&bytes)?;
            Ok(mesh::list_nodes(codec, req).await)
        }
        "/gryonixnexusd.v1.Mesh/DeleteMeshNode" => {
            let req: pb::DeleteMeshNodeRequest = codec.decode(&bytes)?;
            Ok(mesh::delete_node(codec, req).await)
        }
        "/gryonixnexusd.v1.Mesh/PublishMeshNames" => {
            let req: pb::PublishMeshNamesRequest = codec.decode(&bytes)?;
            Ok(mesh::publish_names(codec, req).await)
        }
        "/gryonixnexusd.v1.Models/ListModels" => {
            let req: pb::ListModelsRequest = codec.decode(&bytes)?;
            Ok(models::list(codec, req).await)
        }
        "/gryonixnexusd.v1.Models/PullModel" => {
            // Enveloped, like every other streaming verb on this router.
            let req: pb::PullModelRequest = codec.decode_enveloped(&bytes)?;
            Ok(models::pull(codec, req).await)
        }
        "/gryonixnexusd.v1.Models/DeleteModel" => {
            let req: pb::DeleteModelRequest = codec.decode(&bytes)?;
            Ok(models::delete(codec, req).await)
        }
        // Mods — the catalogue searched from the HOST (see `mods.rs` for why)
        // and the jars the owner sends up. None of these takes a path: the
        // directory comes from the compose project's own config file.
        "/gryonixnexusd.v1.Mods/SearchMods" => {
            let req: pb::SearchModsRequest = codec.decode(&bytes)?;
            Ok(mods::search(codec, req).await)
        }
        "/gryonixnexusd.v1.Mods/ModVersions" => {
            let req: pb::ModVersionsRequest = codec.decode(&bytes)?;
            Ok(mods::versions(codec, req).await)
        }
        "/gryonixnexusd.v1.Mods/ListModFiles" => {
            let req: pb::ListModFilesRequest = codec.decode(&bytes)?;
            Ok(mods::list_files(codec, req).await)
        }
        "/gryonixnexusd.v1.Mods/UploadModFile" => {
            let req: pb::UploadModFileRequest = codec.decode(&bytes)?;
            Ok(mods::upload(codec, req).await)
        }
        "/gryonixnexusd.v1.Mods/DeleteModFile" => {
            let req: pb::DeleteModFileRequest = codec.decode(&bytes)?;
            Ok(mods::delete(codec, req).await)
        }
        "/gryonixnexusd.v1.Dns/SetDynamicDNS" => {
            let req: pb::SetDynamicDnsRequest = codec.decode(&bytes)?;
            Ok(ddns::set(codec, req).await)
        }
        "/gryonixnexusd.v1.Dns/GetDynamicDNS" => {
            let req: pb::GetDynamicDnsRequest = codec.decode(&bytes)?;
            Ok(ddns::get(codec, req).await)
        }
        "/gryonixnexusd.v1.Vpn/ListVpnClients" => {
            let req: pb::ListVpnClientsRequest = codec.decode(&bytes)?;
            Ok(vpn_clients::list_clients(codec, req).await)
        }
        "/gryonixnexusd.v1.Vpn/AddVpnClient" => {
            let req: pb::AddVpnClientRequest = codec.decode(&bytes)?;
            Ok(vpn_clients::add_client(codec, req).await)
        }
        "/gryonixnexusd.v1.Vpn/DeleteVpnClient" => {
            let req: pb::DeleteVpnClientRequest = codec.decode(&bytes)?;
            Ok(vpn_clients::delete_client(codec, req).await)
        }
        "/gryonixnexusd.v1.Vpn/GetVpnClientConfig" => {
            let req: pb::GetVpnClientConfigRequest = codec.decode(&bytes)?;
            Ok(vpn_clients::client_config(codec, req).await)
        }
        // Mailboxes (docker-mailserver). All four are unary: a mailbox verb is
        // one bounded engine call with no partial state, and its answer is the
        // freshly re-read listing. See the Mail service note in the schema.
        "/gryonixnexusd.v1.Mail/ListMailboxes" => {
            let req: pb::ListMailboxesRequest = codec.decode(&bytes)?;
            Ok(mailbox::list_mailboxes(codec, req).await)
        }
        "/gryonixnexusd.v1.Mail/CreateMailbox" => {
            let req: pb::CreateMailboxRequest = codec.decode(&bytes)?;
            Ok(mailbox::create_mailbox(codec, req).await)
        }
        "/gryonixnexusd.v1.Mail/DeleteMailbox" => {
            let req: pb::DeleteMailboxRequest = codec.decode(&bytes)?;
            Ok(mailbox::delete_mailbox(codec, req).await)
        }
        "/gryonixnexusd.v1.Mail/SetMailboxPassword" => {
            let req: pb::SetMailboxPasswordRequest = codec.decode(&bytes)?;
            Ok(mailbox::set_mailbox_password(codec, req).await)
        }
        // DKIM records for whichever mail engine is installed. Read-only and
        // unary, and unlike the Mail RPCs above it calls one of THREE
        // per-engine wrappers rather than one engine directly — see dkim.rs.
        "/gryonixnexusd.v1.Dkim/GetDkimRecords" => {
            let req: pb::GetDkimRecordsRequest = codec.decode(&bytes)?;
            Ok(dkim::get_dkim_records(codec, req).await)
        }
        "/gryonixnexusd.v1.Control/HostMetrics" => {
            let req: pb::HostMetricsRequest = codec.decode_enveloped(&bytes)?;
            Ok(host_metrics_stream(codec, req))
        }
        "/gryonixnexusd.v1.Control/Logs" => {
            let req: pb::LogsRequest = codec.decode_enveloped(&bytes)?;
            logs_stream(codec, req).await
        }
        _ => Ok(connect_error(StatusCode::NOT_FOUND, "not_found", "unknown method")),
    }
}

/// Server-streaming HostMetrics: a background task samples the host once per
/// clamped interval and pushes an enveloped MetricsSample into the channel that
/// feeds the response body. It runs until the client hangs up — at which point
/// the receiver drops, `send` errors, and the loop exits — so there is no
/// server-side end for an intentionally unbounded feed.
fn host_metrics_stream(codec: Codec, req: pb::HostMetricsRequest) -> Resp {
    let interval = match req.interval_seconds as u64 {
        0 => METRICS_DEFAULT_INTERVAL,
        n => n.clamp(1, METRICS_MAX_INTERVAL),
    };
    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(8);

    tokio::spawn(async move {
        let mut sampler = metrics::Sampler::new();
        loop {
            // Sample FIRST, sleep after. The other order made every client wait
            // a whole interval for a reading the host could already give:
            // `Sampler::new` seeds the CPU baseline on construction, so the
            // very first `sample()` is a real one, not a warm-up. Nothing about
            // an unbounded feed says its first frame has to be late, and on the
            // app side that interval was the difference between a card that
            // fills in and one that sits on dashes.
            let sample = sampler.sample();
            let payload = if json {
                serde_json::to_vec(&sample).unwrap_or_default()
            } else {
                sample.encode_to_vec()
            };
            if tx.send(envelope(0x00, &payload)).await.is_err() {
                break; // client gone
            }
            tokio::time::sleep(Duration::from_secs(interval)).await;
        }
    });

    stream_response(json, rx)
}

/// The response head every server-streaming method shares: Connect's streaming
/// content type and a body fed by the producer task's channel.
pub fn stream_response(json: bool, rx: tokio::sync::mpsc::Receiver<Bytes>) -> Resp {
    let content_type = if json {
        "application/connect+json"
    } else {
        "application/connect+proto"
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .body(ChannelBody { rx, trailer_sent: false }.boxed())
        .expect("streaming response builds")
}

/// Server-streaming Logs: resolve the service's containers, then tail each one
/// (`docker logs -f`), multiplexing every line — tagged with its container and
/// stream — into the response. Each child is `kill_on_drop`, so when the client
/// hangs up (the receiver drops and the reader tasks exit) the `docker logs -f`
/// processes are reaped rather than left running.
async fn logs_stream(codec: Codec, req: pb::LogsRequest) -> anyhow::Result<Resp> {
    // A resolution failure (docker missing, etc.) is a real error; an empty set
    // (nothing installed under that id) is a valid, immediately-ending stream.
    let containers = discover::containers_of_service(&req.service_id).await?;
    Ok(tail_all(codec, containers, req.service_id, req.tail))
}

/// Follow a resolved set of containers, whatever resolved them.
///
/// The RESOLVERS differ — a catalog id for `Control/Logs`, a host-reported group
/// key for `Containers/ContainerGroupLogs` — but everything below this line must
/// not: the multiplexing, the `kill_on_drop` reaping and the per-line container
/// tag are the parts that were got right once, and a second copy of them is how
/// a fixed bug comes back.
///
/// `label` is what each line is stamped with, so the client can say what it is
/// looking at without a second lookup.
pub(crate) fn tail_all(
    codec: Codec,
    containers: Vec<String>,
    label: String,
    requested_tail: u32,
) -> Resp {
    let tail = match requested_tail {
        0 => LOGS_DEFAULT_TAIL,
        n => n.clamp(1, LOGS_MAX_TAIL),
    };
    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);

    for container in containers {
        let tx = tx.clone();
        let label = label.clone();
        tokio::spawn(async move { tail_container(container, label, tail, json, tx).await });
    }
    // Drop the template sender so the body ends once every container task has:
    // with zero containers the channel is already closed and the stream is empty.
    drop(tx);

    stream_response(json, rx)
}

/// Tail one container into the shared channel until it ends or the client hangs
/// up. `at` is stamped when the agent reads the line (no timestamp parsing, so
/// no date-library dependency) — close enough for a live follow.
async fn tail_container(container: String, service_id: String, tail: u32, json: bool, tx: Sender<Bytes>) {
    let mut child = match tokio::process::Command::new("docker")
        .args(["logs", "-f", "--tail", &tail.to_string(), &container])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            tracing::warn!(%container, ?err, "docker logs failed to start");
            return;
        }
    };

    let mut out = child.stdout.take().map(|s| tokio::io::BufReader::new(s).lines());
    let mut err = child.stderr.take().map(|s| tokio::io::BufReader::new(s).lines());

    loop {
        tokio::select! {
            line = async { out.as_mut().unwrap().next_line().await }, if out.is_some() => {
                match line {
                    Ok(Some(text)) => {
                        if send_log(&tx, &service_id, &container, "stdout", text, json).await.is_err() {
                            break;
                        }
                    }
                    _ => out = None, // EOF or read error on this pipe
                }
            }
            line = async { err.as_mut().unwrap().next_line().await }, if err.is_some() => {
                match line {
                    Ok(Some(text)) => {
                        if send_log(&tx, &service_id, &container, "stderr", text, json).await.is_err() {
                            break;
                        }
                    }
                    _ => err = None,
                }
            }
            else => break, // both pipes drained
        }
    }
}

/// Frame one log line as a Connect envelope and push it. Errors only when the
/// receiver is gone (client hung up), which the caller treats as "stop".
async fn send_log(
    tx: &Sender<Bytes>,
    service_id: &str,
    container: &str,
    stream: &str,
    text: String,
    json: bool,
) -> Result<(), ()> {
    let line = pb::LogLine {
        service_id: service_id.to_string(),
        at: now_millis(),
        stream: stream.to_string(),
        text,
        container: container.to_string(),
    };
    let payload = if json {
        serde_json::to_vec(&line).unwrap_or_default()
    } else {
        line.encode_to_vec()
    };
    tx.send(envelope(0x00, &payload)).await.map_err(|_| ())
}

/// A Connect message envelope: 1 flag byte, 4-byte big-endian length, payload.
/// Flag 0x00 is a data message; 0x02 marks the end-of-stream trailer.
pub fn envelope(flags: u8, payload: &[u8]) -> Bytes {
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.push(flags);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    Bytes::from(buf)
}

/// Response body fed by the sampler task: yields each pre-framed envelope as it
/// arrives, and closes the stream with the end-of-stream envelope Connect
/// requires.
///
/// **The terminal envelope is emitted HERE, not by the producing verb.** Connect
/// ends every stream with a flag-`0x02` frame — `{}` when the run succeeded —
/// and without it a client cannot tell "the stream finished" from "the
/// connection died after the last event", which is the exact distinction the
/// two-channel error scheme exists to make. Putting it in the one place every
/// streaming verb already funnels through means a new verb cannot forget it;
/// asking each of the eight producers to remember would make the wire a
/// property of whoever wrote the newest one.
///
/// A verb that ends badly sends its own `0x02` trailer (`error_trailer`), so the
/// flag byte of every frame passing through is inspected: once a trailer has
/// gone out, the channel closing adds nothing. Two trailers would be a protocol
/// violation, and the error one carries the reason.
struct ChannelBody {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
    /// Whether an end-of-stream envelope has already reached the client —
    /// either the verb's own error trailer or the success trailer below.
    trailer_sent: bool,
}

/// The end-of-stream envelope of a stream that ran to completion: an empty JSON
/// object, the Connect spelling of "no error".
fn success_trailer() -> Bytes {
    envelope(END_OF_STREAM_FLAG, b"{}")
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(bytes)) => {
                if bytes.first() == Some(&END_OF_STREAM_FLAG) {
                    self.trailer_sent = true;
                }
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(None) if !self.trailer_sent => {
                self.trailer_sent = true;
                Poll::Ready(Some(Ok(Frame::data(success_trailer()))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Flag byte marking the end-of-stream envelope: the trailer, which is `{}` on
/// success and carries `{"error": …}` when the stream ends badly.
pub const END_OF_STREAM_FLAG: u8 = 0x02;

/// The end-of-stream envelope carrying a Connect error. Every streaming
/// operation ends with this when it fails: a streamed operation carries no exit
/// status of its own, so without the trailer a failed run would look exactly
/// like a successful one — the same lesson the wrapper scripts learned with
/// their completion markers.
pub fn error_trailer(code: &str, message: &str) -> Bytes {
    let body = serde_json::json!({ "error": { "code": code, "message": message } }).to_string();
    envelope(END_OF_STREAM_FLAG, body.as_bytes())
}

#[derive(Clone, Copy)]
pub enum Codec {
    Json,
    Proto,
}

impl Codec {
    fn from_content_type(ct: Option<&str>) -> Self {
        match ct {
            Some(v) if v.contains("json") => Codec::Json,
            _ => Codec::Proto,
        }
    }

    fn decode<T>(&self, bytes: &[u8]) -> anyhow::Result<T>
    where
        T: prost::Message + Default + serde::de::DeserializeOwned,
    {
        match self {
            Codec::Json if bytes.is_empty() => Ok(T::default()),
            Codec::Json => Ok(serde_json::from_slice(bytes)?),
            Codec::Proto => Ok(T::decode(bytes)?),
        }
    }

    /// Decode a single streaming-request message: server-streaming calls send
    /// exactly one enveloped message, so strip the 5-byte prefix first. An empty
    /// or truncated body decodes as the default request.
    fn decode_enveloped<T>(&self, bytes: &[u8]) -> anyhow::Result<T>
    where
        T: prost::Message + Default + serde::de::DeserializeOwned,
    {
        self.decode(strip_envelope(bytes))
    }

    /// Encode one streamed message the way this codec frames it (protobuf
    /// binary by default, JSON when the client asked for the debuggable wire).
    pub fn encode_payload<T>(&self, msg: &T) -> Vec<u8>
    where
        T: prost::Message + serde::Serialize,
    {
        match self {
            Codec::Json => serde_json::to_vec(msg).unwrap_or_default(),
            Codec::Proto => msg.encode_to_vec(),
        }
    }

    /// Decode a payload this codec encoded — the inverse of `encode_payload`.
    ///
    /// Only one caller needs it: `ProvisionHost` is unary, so the step events its
    /// shared implementation emits have no stream to travel on and are read back
    /// out of the channel instead (`install::execute::drain_notes`). Failure is
    /// `None` rather than an error: a note nobody can decode is a note not worth
    /// failing a provisioning run over.
    pub fn decode_payload<T>(&self, bytes: &[u8]) -> Option<T>
    where
        T: prost::Message + Default + serde::de::DeserializeOwned,
    {
        match self {
            Codec::Json => serde_json::from_slice(bytes).ok(),
            Codec::Proto => T::decode(bytes).ok(),
        }
    }

    pub fn encode<T>(&self, msg: &T) -> anyhow::Result<Resp>
    where
        T: prost::Message + serde::Serialize,
    {
        let (body, ct) = match self {
            Codec::Json => (serde_json::to_vec(msg)?, "application/json"),
            Codec::Proto => (msg.encode_to_vec(), "application/proto"),
        };
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, ct)
            .body(Full::new(Bytes::from(body)).boxed())?)
    }
}

/// The payload of a single Connect envelope: skip the flag byte + 4-byte length,
/// return the declared payload (clamped to what actually arrived).
fn strip_envelope(bytes: &[u8]) -> &[u8] {
    if bytes.len() < 5 {
        return &[];
    }
    let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    let end = (5 + len).min(bytes.len());
    &bytes[5..end]
}

/// The header every client puts its installation id in. Lower-case because
/// hyper normalises header names, and a comparison against a mixed-case
/// constant would silently never match.
const DEVICE_HEADER: &str = "x-gryonix-device";

/// **The one place the auto-logout window is enforced.**
///
/// `Some(response)` means "answer this and do not dispatch". Three things are
/// deliberate:
///
/// * **With no window set, nothing changes at all.** The default is "never",
///   which is what every host in the field has today, and on that setting an
///   unidentified caller is served exactly as before. A security gate that
///   turns itself on during an upgrade would lock owners out of their own
///   servers.
/// * **With a window set, a caller that will not name itself is refused.**
///   Otherwise the window would be advice: any client could omit the header
///   and be served forever, and an expired phone could omit it too.
/// * **`Pair` is always allowed through.** It is the way BACK IN, and it is not
///   an open door: it consumes a one-time code that only somebody with access
///   to the server itself can read.
///
/// The refusal message begins with a stable marker (`session_expired`,
/// `device_not_paired`, `device_unidentified`) because both apps have to tell
/// these apart to know whether to offer "sign in again" or "update the app",
/// and the Connect code alone (`unauthenticated`) cannot say which.
fn session_refusal(
    parts: &hyper::http::request::Parts,
    path: &str,
    store: &Arc<Mutex<Store>>,
) -> anyhow::Result<Option<Resp>> {
    if path == "/gryonixnexusd.v1.Pairing/Pair" {
        return Ok(None);
    }
    let uid = parts
        .headers
        .get(DEVICE_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();

    let (policy, session) = {
        let store = lock(store);
        // Asked even when the window is "never": this is also what records
        // `last_seen_at`, and a list where that column is only filled in on
        // servers with a policy would be a column that looks broken.
        let session = store.device_session(&uid)?;
        (store.session_policy()?, session)
    };
    if policy.auto_logout_months == 0 {
        return Ok(None);
    }
    let refusal = match session {
        crate::state::DeviceSession::Live => return Ok(None),
        crate::state::DeviceSession::Unidentified => (
            "device_unidentified",
            "this server signs devices out on a schedule, and this client did not say which              device it is — update the app",
        ),
        crate::state::DeviceSession::Unknown => (
            "device_not_paired",
            "this device is not paired with this server",
        ),
        crate::state::DeviceSession::Expired => (
            "session_expired",
            "this device's session has run out — sign in again to keep using this server",
        ),
    };
    Ok(Some(connect_error(
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        &format!("{}: {}", refusal.0, refusal.1),
    )))
}

/// **A panicking RPC must not take the next one down with it.** A poisoned
/// mutex turns one failure into every failure — recorded in GOTCHAS after a
/// negative control did exactly that to seven tests at once.
/// **After a vault write, put the rows that are SERVICE SECRETS where the
/// service reads them.**
///
/// Called on the way out of both vault writes rather than from inside the
/// store, because the store's job ends at "the rows are saved" and this one
/// touches the filesystem and docker. Both callers pass the snapshot they are
/// about to return, so what lands on disk is exactly what the client is told
/// the server holds.
///
/// **A failure here never fails the write.** The keys are already stored and
/// already replicated to the other device; a host whose gateway is absent,
/// stopped, or whose `/etc` is momentarily unwritable is a host that saved a
/// key, and turning that into an error would make saving one fail on every
/// deployment that has no gateway at all. It is logged and left.
fn reconcile_service_secrets(snapshot: &pb::VaultSnapshot) {
    if let Err(err) = crate::install::llm_keys::reconcile(&snapshot.entries) {
        eprintln!("vault: rendering the model provider keys failed: {err:#}");
    }
}

fn lock(store: &Arc<Mutex<Store>>) -> std::sync::MutexGuard<'_, Store> {
    store.lock().unwrap_or_else(|err| err.into_inner())
}

pub fn connect_error(status: StatusCode, code: &str, message: &str) -> Resp {
    let body = serde_json::json!({ "code": code, "message": message }).to_string();
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)).boxed())
        .expect("static error response builds")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_frames_flag_and_big_endian_length() {
        let framed = envelope(0x00, b"hello");
        assert_eq!(framed[0], 0x00);
        assert_eq!(&framed[1..5], &[0, 0, 0, 5]); // length 5, big-endian
        assert_eq!(&framed[5..], b"hello");
    }

    #[test]
    fn strip_envelope_roundtrips_the_payload() {
        let framed = envelope(0x00, b"payload");
        assert_eq!(strip_envelope(&framed), b"payload");
    }

    // ─────────────── who is calling, and is the door still open ───────────────

    fn parts_for(path: &str, device: Option<&str>) -> hyper::http::request::Parts {
        let mut builder = Request::builder().uri(path);
        if let Some(device) = device {
            builder = builder.header(DEVICE_HEADER, device);
        }
        builder.body(()).expect("request builds").into_parts().0
    }

    fn store_with_device() -> Arc<Mutex<Store>> {
        let store = Store::in_memory().expect("in-memory store");
        store.pair("ssh-ed25519 AAAA", "iPhone", "uid-a").expect("pair");
        Arc::new(Mutex::new(store))
    }

    async fn refusal_message(resp: Resp) -> String {
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        String::from_utf8_lossy(&bytes).to_string()
    }

    const ANY_VERB: &str = "/gryonixnexusd.v1.Control/GetState";

    /// The default. Every host in the field is on it, and an upgrade that
    /// started refusing calls would lock owners out of their own servers.
    #[test]
    fn with_no_window_set_an_anonymous_caller_is_served_exactly_as_before() {
        let store = store_with_device();
        let parts = parts_for(ANY_VERB, None);
        assert!(session_refusal(&parts, ANY_VERB, &store).unwrap().is_none());
    }

    #[tokio::test]
    async fn with_a_window_set_a_caller_that_will_not_name_itself_is_refused() {
        let store = store_with_device();
        store.lock().unwrap().set_session_policy(3).unwrap();
        let parts = parts_for(ANY_VERB, None);
        let refusal = session_refusal(&parts, ANY_VERB, &store).unwrap().expect("refused");
        assert_eq!(refusal.status(), StatusCode::UNAUTHORIZED);
        let body = refusal_message(refusal).await;
        assert!(body.contains("device_unidentified"), "got: {body}");
        assert!(body.contains("unauthenticated"), "got: {body}");
    }

    /// Without this the window would be advice: an expired phone could send any
    /// id at all and be served.
    #[tokio::test]
    async fn an_id_nobody_paired_under_is_refused_too() {
        let store = store_with_device();
        store.lock().unwrap().set_session_policy(3).unwrap();
        let parts = parts_for(ANY_VERB, Some("uid-somebody-else"));
        let refusal = session_refusal(&parts, ANY_VERB, &store).unwrap().expect("refused");
        let body = refusal_message(refusal).await;
        assert!(body.contains("device_not_paired"), "got: {body}");
    }

    #[tokio::test]
    async fn a_device_past_its_window_is_told_which_kind_of_no_this_is() {
        let store = store_with_device();
        store.lock().unwrap().set_session_policy(1).unwrap();
        store
            .lock()
            .unwrap()
            .set_expiry_for_test("uid-a", 1)
            .unwrap();
        let parts = parts_for(ANY_VERB, Some("uid-a"));
        let refusal = session_refusal(&parts, ANY_VERB, &store).unwrap().expect("refused");
        let body = refusal_message(refusal).await;
        assert!(body.contains("session_expired"), "got: {body}");
    }

    #[test]
    fn a_paired_device_inside_its_window_is_let_through() {
        let store = store_with_device();
        store.lock().unwrap().set_session_policy(12).unwrap();
        let parts = parts_for(ANY_VERB, Some("uid-a"));
        assert!(session_refusal(&parts, ANY_VERB, &store).unwrap().is_none());
    }

    /// The way back in. Refusing `Pair` to an expired device would leave the
    /// owner with a server nothing on this phone can talk to — and it is not an
    /// open door, it still spends a one-time code only the server can print.
    #[test]
    fn pairing_stays_open_to_a_device_whose_session_has_run_out() {
        let store = store_with_device();
        store.lock().unwrap().set_session_policy(1).unwrap();
        store.lock().unwrap().set_expiry_for_test("uid-a", 1).unwrap();
        let path = "/gryonixnexusd.v1.Pairing/Pair";
        let parts = parts_for(path, Some("uid-a"));
        assert!(session_refusal(&parts, path, &store).unwrap().is_none());
    }

    #[test]
    fn strip_envelope_tolerates_short_and_truncated_input() {
        assert_eq!(strip_envelope(b""), b"");
        assert_eq!(strip_envelope(&[0x00, 0x00]), b"");
        // Header claims 99 bytes but only 3 follow: clamp, don't panic.
        let truncated = [0x00, 0, 0, 0, 99, b'a', b'b', b'c'];
        assert_eq!(strip_envelope(&truncated), b"abc");
    }

    #[test]
    fn decode_enveloped_reads_the_inner_request() {
        let req = pb::HostMetricsRequest { interval_seconds: 7 };
        let framed = envelope(0x00, &req.encode_to_vec());
        let decoded: pb::HostMetricsRequest = Codec::Proto.decode_enveloped(&framed).unwrap();
        assert_eq!(decoded.interval_seconds, 7);
    }

    /// Drive a `ChannelBody` to exhaustion and return the frames a client would
    /// actually read off the wire — the only level at which the terminal
    /// envelope is observable, since the producing verb never puts it on the
    /// channel.
    async fn drain_body(rx: tokio::sync::mpsc::Receiver<Bytes>) -> Vec<Bytes> {
        use http_body_util::BodyExt;
        let mut body = ChannelBody { rx, trailer_sent: false };
        let mut frames = Vec::new();
        while let Some(frame) = body.frame().await {
            frames.push(frame.unwrap().into_data().unwrap());
        }
        frames
    }

    #[tokio::test]
    async fn a_stream_that_ends_well_closes_with_an_empty_end_of_stream_envelope() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(8);
        tx.send(envelope(0x00, b"event")).await.unwrap();
        drop(tx); // the verb finished and dropped its sender

        let frames = drain_body(rx).await;
        assert_eq!(frames.len(), 2, "the data frame plus one trailer");
        assert_eq!(frames[0][0], 0x00);
        let trailer = &frames[1];
        assert_eq!(trailer[0], END_OF_STREAM_FLAG);
        assert_eq!(strip_envelope(trailer), b"{}", "success is the empty error object");
    }

    #[tokio::test]
    async fn a_stream_that_sent_its_own_error_trailer_does_not_get_a_second_one() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(8);
        tx.send(envelope(0x00, b"event")).await.unwrap();
        tx.send(error_trailer("internal", "it broke")).await.unwrap();
        drop(tx);

        let frames = drain_body(rx).await;
        assert_eq!(frames.len(), 2, "the data frame plus the verb's own trailer, nothing appended");
        let trailer = &frames[1];
        assert_eq!(trailer[0], END_OF_STREAM_FLAG);
        let body: serde_json::Value = serde_json::from_slice(strip_envelope(trailer)).unwrap();
        assert_eq!(body["error"]["code"], "internal");
    }

    #[tokio::test]
    async fn even_a_stream_with_no_events_at_all_carries_the_trailer() {
        // Logs of a service with zero containers: the channel is closed before
        // the body is ever polled, and an empty body would leave a conformant
        // client waiting for an end it never sees.
        let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(8);
        drop(tx);

        let frames = drain_body(rx).await;
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][0], END_OF_STREAM_FLAG);
        assert_eq!(strip_envelope(&frames[0]), b"{}");
    }
}
