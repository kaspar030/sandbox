//! Mini-init process for PID 1 inside the container.
//!
//! When --init is specified, this runs as PID 1 and:
//! 1. Forwards signals to the child process (or handles them in idle mode)
//! 2. Reaps zombie processes
//! 3. Exits with the child's exit code (or 0 on SIGTERM in idle mode)

/// Run as PID 1 inside the container.
///
/// If `command` is empty, runs in **idle mode**: no child process is forked,
/// init just stays alive as PID 1, reaps zombies from `exec`'d processes,
/// and exits cleanly on SIGTERM. This is the default for `sandbox create`
/// without a command — the container stays alive for `sandbox exec`.
///
/// If `command` is non-empty, forks the command as a child, then:
/// - Forwards SIGTERM, SIGINT, SIGHUP, SIGUSR1, SIGUSR2 to the child
/// - Reaps zombies via waitpid(-1, WNOHANG)
/// - Waits for the main child to exit
/// - Exits with the child's exit code
pub fn run_init(command: &[String]) -> ! {
    // Idle mode: no command, just be PID 1
    if command.is_empty() {
        run_idle();
    }

    // Set up signal forwarding
    let child_pid = match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Child) => {
            // Child: exec the actual command
            exec_command(command);
        }
        Ok(nix::unistd::ForkResult::Parent { child }) => child.as_raw(),
        Err(e) => {
            eprintln!("sandbox-init: fork failed: {e}");
            std::process::exit(1);
        }
    };

    // Parent: PID 1 init process
    // Set up signal handlers that forward to child
    setup_signal_forwarding(child_pid);

    // Main loop: wait for children
    use nix::sys::wait::{WaitStatus, waitpid};

    let child = nix::unistd::Pid::from_raw(child_pid);

    loop {
        // Wait for any child (pid -1)
        match waitpid(None, None) {
            Ok(WaitStatus::Exited(pid, code)) if pid == child => {
                std::process::exit(code);
            }
            Ok(WaitStatus::Signaled(pid, sig, _)) if pid == child => {
                std::process::exit(128 + sig as i32);
            }
            Ok(_) => {
                // Some other child (zombie) was reaped — continue waiting
            }
            Err(nix::Error::ECHILD) => {
                // No more children
                std::process::exit(0);
            }
            Err(nix::Error::EINTR) => continue,
            Err(_) => continue,
        }
    }
}

/// Idle mode: PID 1 with no child process.
///
/// Reaps zombies (from exec'd processes) and exits on SIGTERM/SIGINT.
fn run_idle() -> ! {
    // Set up signal handlers that cause clean exit
    unsafe {
        libc::signal(
            libc::SIGTERM,
            idle_exit_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            idle_exit_handler as *const () as libc::sighandler_t,
        );
    }

    use nix::sys::wait::{WaitPidFlag, waitpid};

    // Main loop: reap zombies, sleep when no children
    loop {
        match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
            Ok(nix::sys::wait::WaitStatus::StillAlive) | Err(nix::Error::ECHILD) => {
                // No children to reap — sleep until signal
                nix::unistd::pause();
            }
            Err(nix::Error::EINTR) => continue,
            _ => continue, // reaped a zombie, check for more
        }
    }
}

extern "C" fn idle_exit_handler(_sig: libc::c_int) {
    std::process::exit(0);
}

fn setup_signal_forwarding(child_pid: libc::pid_t) {
    // Store the child PID in a static for signal handlers
    CHILD_PID.store(child_pid, std::sync::atomic::Ordering::SeqCst);

    let signals = [
        libc::SIGTERM,
        libc::SIGINT,
        libc::SIGHUP,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGQUIT,
    ];

    for &sig in &signals {
        unsafe {
            libc::signal(sig, forward_signal as *const () as libc::sighandler_t);
        }
    }
}

static CHILD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn forward_signal(sig: libc::c_int) {
    let pid = CHILD_PID.load(std::sync::atomic::Ordering::SeqCst);
    if pid > 0 {
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

fn exec_command(command: &[String]) -> ! {
    if command.is_empty() {
        eprintln!("sandbox-init: no command specified");
        std::process::exit(1);
    }

    let c_program = std::ffi::CString::new(command[0].as_str()).unwrap_or_else(|_| {
        eprintln!("sandbox-init: invalid command");
        std::process::exit(1);
    });

    let c_args: Vec<std::ffi::CString> = command
        .iter()
        .map(|a| std::ffi::CString::new(a.as_str()).unwrap())
        .collect();

    // nix::unistd::execvp only returns on error
    let err = nix::unistd::execvp(&c_program, &c_args).unwrap_err();
    eprintln!("sandbox-init: exec failed: {err}");
    std::process::exit(1);
}
