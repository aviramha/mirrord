use std::{
    fs,
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
    process::{Command, Stdio},
};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Information stored in the debugger lock file.
#[derive(Debug, Serialize, Deserialize)]
struct LockFileInfo {
    addr: SocketAddr,
    pid: u32,
    token: String,
}

/// Manages the debugger process lifecycle.
pub struct DebuggerLauncher;

impl DebuggerLauncher {
    /// Ensure a debugger instance is running.
    ///
    /// Returns the debugger address and authentication token.
    /// If a debugger is already running, reuses it. Otherwise, spawns a new one.
    pub async fn ensure_running() -> Result<(SocketAddr, String), io::Error> {
        let lock_path = Self::lock_file_path()?;

        // Try to read existing lock file
        if let Ok(contents) = fs::read_to_string(&lock_path) {
            if let Ok(info) = serde_json::from_str::<LockFileInfo>(&contents) {
                // Check if the process is still alive
                if Self::is_process_alive(info.pid) {
                    debug!(
                        "Reusing existing debugger at {} (PID {})",
                        info.addr, info.pid
                    );
                    return Ok((info.addr, info.token));
                } else {
                    warn!("Stale lock file found, cleaning up");
                    let _ = fs::remove_file(&lock_path);
                }
            }
        }

        // No running debugger, spawn a new one
        info!("Spawning new debugger process");
        Self::spawn_debugger(&lock_path).await
    }

    /// Spawn a new debugger process.
    async fn spawn_debugger(lock_path: &PathBuf) -> Result<(SocketAddr, String), io::Error> {
        // Get the current executable path (mirrord CLI)
        let exe = std::env::current_exe()?;

        // Spawn the debugger as a background process
        let mut child = Command::new(&exe)
            .arg("debugger")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        let pid = child.id();
        debug!("Spawned debugger process with PID {}", pid);

        // Read the address and token from stdout
        let stdout = child.stdout.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "Failed to capture debugger stdout")
        })?;

        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        std::io::BufRead::read_line(&mut reader, &mut line)?;

        // Parse output: "addr:token"
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() != 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid debugger output: {}", line),
            ));
        }

        let addr: SocketAddr = format!("{}:{}", parts[0], parts[1])
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let token = parts[2].to_owned();

        // Write lock file
        let lock_info = LockFileInfo {
            addr,
            pid,
            token: token.clone(),
        };
        let json = serde_json::to_string(&lock_info)?;
        fs::write(lock_path, json)?;

        info!("Debugger started at {} (PID {})", addr, pid);

        Ok((addr, token))
    }

    /// Check if a process is still alive.
    #[cfg(unix)]
    fn is_process_alive(pid: u32) -> bool {
        use nix::{
            sys::signal::{Signal, kill},
            unistd::Pid,
        };

        // Send signal 0 to check if process exists
        kill(Pid::from_raw(pid as i32), Signal::SIGCONT).is_ok()
    }

    #[cfg(windows)]
    fn is_process_alive(pid: u32) -> bool {
        // On Windows, try to open the process handle
        use windows::Win32::{
            Foundation::CloseHandle,
            System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION},
        };

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
                let _ = CloseHandle(handle);
                true
            } else {
                false
            }
        }
    }

    /// Get the path to the lock file.
    fn lock_file_path() -> io::Result<PathBuf> {
        let mut path = dirs::home_dir()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Home directory not found"))?;

        path.push(".mirrord");

        // Create directory if it doesn't exist
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }

        path.push("debugger.lock");

        Ok(path)
    }
}

/// Run the debugger server (invoked by `mirrord debugger` command).
pub async fn run_debugger() -> Result<(), io::Error> {
    use super::start_server;

    let (addr, token) = start_server().await?;

    // Print address and token to stdout for the launcher to read
    // Format: "ip:port:token"
    println!("{}:{}", addr, token);
    io::stdout().flush()?;

    // Keep running until interrupted
    tokio::signal::ctrl_c().await?;

    Ok(())
}
