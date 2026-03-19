//! Parse /etc/subuid and /etc/subgid for subordinate ID ranges.
//!
//! These files define which host UID/GID ranges a user is allowed to
//! map into user namespaces. Format: `name_or_uid:start:count` per line.

/// A subordinate ID range.
#[derive(Debug, Clone)]
pub struct SubIdRange {
    /// Starting host UID/GID.
    pub start: u32,
    /// Number of IDs in the range.
    pub count: u32,
}

/// Read subordinate ID ranges for a given user from a subid file.
///
/// Looks up by username first, then by numeric UID string.
/// Returns all matching ranges (there can be multiple lines per user).
/// Returns an empty Vec if the file doesn't exist or no entry matches.
pub fn read_subid_ranges(path: &str, username: &str, uid: u32) -> Vec<SubIdRange> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let uid_str = uid.to_string();
    let mut ranges = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() != 3 {
            continue;
        }

        let name = parts[0];
        if name != username && name != uid_str {
            continue;
        }

        let start: u32 = match parts[1].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let count: u32 = match parts[2].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        ranges.push(SubIdRange { start, count });
    }

    ranges
}

/// Read subordinate UID ranges for the current user.
pub fn read_subuid(username: &str, uid: u32) -> Vec<SubIdRange> {
    read_subid_ranges("/etc/subuid", username, uid)
}

/// Read subordinate GID ranges for the current user.
pub fn read_subgid(username: &str, gid: u32) -> Vec<SubIdRange> {
    read_subid_ranges("/etc/subgid", username, gid)
}

/// Get the current username from the environment or /etc/passwd.
pub fn current_username() -> Option<String> {
    // Try environment first
    if let Ok(user) = std::env::var("USER") {
        if !user.is_empty() {
            return Some(user);
        }
    }

    // Fall back to getpwuid
    let uid = nix::unistd::getuid();
    nix::unistd::User::from_uid(uid)
        .ok()
        .flatten()
        .map(|u| u.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_subid_lines() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("subuid");
        std::fs::write(
            &path,
            "root:100000:65536\nnobody:200000:65536\nroot:300000:10000\n1000:400000:65536\n",
        )
        .unwrap();

        let ranges = read_subid_ranges(path.to_str().unwrap(), "root", 0);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, 100000);
        assert_eq!(ranges[0].count, 65536);
        assert_eq!(ranges[1].start, 300000);
        assert_eq!(ranges[1].count, 10000);

        // Lookup by numeric UID
        let ranges = read_subid_ranges(path.to_str().unwrap(), "someuser", 1000);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, 400000);
    }

    #[test]
    fn test_missing_file() {
        let ranges = read_subid_ranges("/nonexistent/subuid", "root", 0);
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_no_match() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("subuid");
        std::fs::write(&path, "alice:100000:65536\n").unwrap();

        let ranges = read_subid_ranges(path.to_str().unwrap(), "bob", 999);
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_comments_and_empty_lines() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("subuid");
        std::fs::write(&path, "# comment\n\nroot:100000:65536\n\n").unwrap();

        let ranges = read_subid_ranges(path.to_str().unwrap(), "root", 0);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, 100000);
    }
}
