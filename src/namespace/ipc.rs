//! IPC namespace.
//!
//! The IPC namespace is created by clone3 with CLONE_NEWIPC.
//! No additional setup is required — the isolation is automatic.
//! This module exists for completeness and future extensibility
//! (e.g., setting POSIX MQ limits).

// IPC namespace requires no child-side setup beyond the CLONE_NEWIPC flag.
// All System V IPC objects (semaphores, shared memory, message queues)
// and POSIX message queues are automatically isolated.
