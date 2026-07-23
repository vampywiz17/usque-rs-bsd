use std::collections::HashMap;
use std::process::Command;

pub fn run_hook(path: &str, extra_env: &HashMap<String, String>) {
    if path.is_empty() {
        return;
    }

    let mut cmd = Command::new(path);
    cmd.envs(extra_env);
    match cmd.spawn() {
        Ok(_) => tracing::debug!("started hook: {path}"),
        Err(err) => tracing::warn!("failed to start hook {path}: {err}"),
    }
}
