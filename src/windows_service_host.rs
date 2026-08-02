use std::{ffi::OsString, path::PathBuf, sync::OnceLock, time::Duration};

use anyhow::{Context, Result};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

const SERVICE_NAME: &str = "SudoServer";
static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

pub fn dispatch(config: PathBuf) -> Result<()> {
    CONFIG_PATH
        .set(config)
        .map_err(|_| anyhow::anyhow!("service configuration was already initialized"))?;
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("failed to connect to the Windows Service Control Manager")
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        tracing::error!(%error, "Windows service failed");
    }
}

fn run_service() -> Result<()> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let mut shutdown_tx = Some(shutdown_tx);
    let event_handler = move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(sender) = shutdown_tx.take() {
                let _ = sender.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(SERVICE_NAME, event_handler)?;
    status.set_service_status(service_status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::Win32(0),
    ))?;

    let path = CONFIG_PATH
        .get()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing service configuration path"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(super::serve_until(path, true, async move {
        let _ = shutdown_rx.await;
    }));

    let exit_code = if result.is_ok() {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    status.set_service_status(service_status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
    ))?;
    result
}

fn service_status(
    state: ServiceState,
    controls: ServiceControlAccept,
    exit_code: ServiceExitCode,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: controls,
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}
