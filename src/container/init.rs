//! Mini-init process for PID 1 inside the container.
//!
//! When --init is specified, this runs as PID 1 and:
//! 1. Forwards signals to the child process
//! 2. Reaps zombie processes
//! 3. Exits with the child's exit code

/// Run as PID 1 inside the container.
///
/// Forks the actual command as a child, then:
/// - Forwards SIGTERM, SIGINT, SIGHUP, SIGUSR1, SIGUSR2 to the child
/// - Reaps zombies via waitpid(-1, WNOHANG)
/// - Waits for the main child to exit
/// - Exits with the child's exit code
pub fn run_init(command: &[String]) -> ! {
    // Set up signal forwarding
    let child_pid = match unsafe { libc::fork() } {
        -1 => {
            eprintln!("sandbox-init: fork failed: {}", std::io::Error::last_os_error());
            std::process::exit(1);
        }
        0 => {
            // Child: exec the actual command
            exec_command(command);
        }
        pid => pid,
    };

    // Parent: PID 1 init process
    // Set up signal handlers that forward to child
    setup_signal_forwarding(child_pid);

    // Main loop: wait for children
    loop {
        let mut status: i32 = 0;
        let waited = unsafe { libc::waitpid(-1, &mut status, 0) };

        if waited < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ECHILD) {
                // No more children — our main child must have exited
                // This shouldn't happen if we're properly tracking, but exit cleanly
                std::process::exit(0);
            }
            // EINTR is expected when signals arrive
            continue;
        }

        if waited == child_pid {
            // Our main child exited
            let exit_code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                128 + libc::WTERMSIG(status)
            } else {
                1
            };
            std::process::exit(exit_code);
        }

        // Some other child (zombie) was reaped — continue waiting
    }
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
    let c_arg_ptrs: Vec<*const libc::c_char> = c_args
        .iter()
        .map(|a| a.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    unsafe {
        libc::execvp(c_program.as_ptr(), c_arg_ptrs.as_ptr());
    }

    // If execvp returns, it failed
    eprintln!(
        "sandbox-init: exec failed: {}",
        std::io::Error::last_os_error()
    );
    std::process::exit(1);
}
