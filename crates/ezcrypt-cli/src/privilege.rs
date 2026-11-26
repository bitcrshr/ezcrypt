//! Running as root: checking for it, and rerunning ezcrypt with sudo.

use std::process::Command;

#[cfg(unix)]
use anyhow::anyhow;
use anyhow::{Context, Result};

pub fn is_root() -> Result<bool> {
    let out = Command::new("id")
        .arg("-u")
        .output()
        .context("cannot run id")?;
    Ok(String::from_utf8_lossy(&out.stdout).trim() == "0")
}

/// Rerun this binary as root with the same arguments, through sudo (or doas),
/// after printing `why` (a full sentence). Uses our own absolute path because
/// `sudo ezcrypt` fails when ezcrypt is in ~/.local/bin, which sudo's
/// secure_path leaves out. Returns only on failure.
#[cfg(unix)]
pub fn escalate(why: &str) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().context("cannot locate the running ezcrypt")?;
    let on_path = |program: &str| {
        std::env::var_os("PATH")
            .is_some_and(|path| std::env::split_paths(&path).any(|d| d.join(program).is_file()))
    };
    let Some(tool) = ["sudo", "doas"].into_iter().find(|t| on_path(t)) else {
        anyhow::bail!("{why} Neither sudo nor doas was found; run ezcrypt as root.");
    };
    eprintln!("{why} Running it with {tool}.");
    let err = Command::new(tool)
        .arg(&exe)
        .args(std::env::args_os().skip(1))
        .exec();
    Err(anyhow!(err).context(format!("cannot run {tool}")))
}

#[cfg(not(unix))]
pub fn escalate(why: &str) -> Result<()> {
    anyhow::bail!("{why} Rerun it from an elevated terminal.")
}
