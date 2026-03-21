//! Parse /etc/passwd and /etc/group to resolve user/group identity.

/// An entry from /etc/passwd.
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

/// Look up a user by UID in /etc/passwd (reads from current root).
/// Call after chroot/pivot_root to read the container's passwd file.
pub fn lookup_uid(uid: u32) -> Option<PasswdEntry> {
    let contents = std::fs::read_to_string("/etc/passwd").ok()?;
    parse_passwd_uid(&contents, uid)
}

/// Look up a user by name in /etc/passwd (reads from current root).
pub fn lookup_name(name: &str) -> Option<PasswdEntry> {
    let contents = std::fs::read_to_string("/etc/passwd").ok()?;
    parse_passwd_name(&contents, name)
}

/// Parse passwd file contents and find entry matching uid.
fn parse_passwd_uid(contents: &str, uid: u32) -> Option<PasswdEntry> {
    // Format: name:password:uid:gid:gecos:home:shell
    for line in contents.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 {
            continue;
        }
        let entry_uid: u32 = match fields[2].parse() {
            Ok(u) => u,
            Err(_) => continue,
        };
        if entry_uid == uid {
            return Some(PasswdEntry {
                name: fields[0].to_string(),
                uid: entry_uid,
                gid: fields[3].parse().unwrap_or(0),
                home: fields[5].to_string(),
                shell: fields[6].to_string(),
            });
        }
    }
    None
}

/// Parse passwd file contents and find entry matching name.
fn parse_passwd_name(contents: &str, name: &str) -> Option<PasswdEntry> {
    for line in contents.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 {
            continue;
        }
        if fields[0] == name {
            return Some(PasswdEntry {
                name: fields[0].to_string(),
                uid: fields[2].parse().unwrap_or(65534),
                gid: fields[3].parse().unwrap_or(65534),
                home: fields[5].to_string(),
                shell: fields[6].to_string(),
            });
        }
    }
    None
}

/// Look up a group by name in /etc/group (reads from current root).
pub fn lookup_group_name(name: &str) -> Option<u32> {
    let contents = std::fs::read_to_string("/etc/group").ok()?;
    parse_group_name(&contents, name)
}

/// Parse /etc/group and find GID matching name.
fn parse_group_name(contents: &str, name: &str) -> Option<u32> {
    // Format: name:password:gid:members
    for line in contents.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 3 {
            continue;
        }
        if fields[0] == name {
            return fields[2].parse().ok();
        }
    }
    None
}

/// Get all supplementary group GIDs for a username from /etc/group.
/// Returns a vec of GIDs for groups that list this username as a member.
pub fn lookup_supplementary_groups(username: &str) -> Vec<u32> {
    let contents = match std::fs::read_to_string("/etc/group") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    parse_supplementary_groups(&contents, username)
}

/// Parse /etc/group and find all groups that list username as a member.
fn parse_supplementary_groups(contents: &str, username: &str) -> Vec<u32> {
    let mut gids = Vec::new();
    // Format: name:password:gid:user1,user2,...
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 4 {
            continue;
        }
        let gid: u32 = match fields[2].parse() {
            Ok(g) => g,
            Err(_) => continue,
        };
        // Check member list (comma-separated)
        let members = fields[3];
        if !members.is_empty() {
            for member in members.split(',') {
                if member.trim() == username {
                    gids.push(gid);
                    break;
                }
            }
        }
    }
    gids
}

/// Resolved user identity: uid, gid, and optional username.
pub struct ResolvedUser {
    pub uid: u32,
    pub gid: u32,
    pub name: Option<String>,
}

/// Resolve a user spec string into uid/gid.
///
/// Supports OCI/Docker formats:
/// - "UID" (e.g., "1000")
/// - "UID:GID" (e.g., "1000:1000")
/// - "name" (e.g., "nobody") — looked up in /etc/passwd
/// - "name:group" (e.g., "nobody:nogroup") — looked up in /etc/passwd + /etc/group
///
/// Must be called after chroot/pivot_root to read the container's files.
pub fn resolve_user_spec(spec: &str) -> Option<ResolvedUser> {
    if spec.is_empty() {
        return None;
    }

    if let Some((user_part, group_part)) = spec.split_once(':') {
        // UID:GID or name:group
        let uid = if let Ok(u) = user_part.parse::<u32>() {
            u
        } else {
            // name → look up in /etc/passwd
            lookup_name(user_part).map(|pw| pw.uid)?
        };
        let gid = if let Ok(g) = group_part.parse::<u32>() {
            g
        } else {
            // group name → look up in /etc/group
            lookup_group_name(group_part)?
        };
        let name = lookup_uid(uid).map(|pw| pw.name);
        Some(ResolvedUser { uid, gid, name })
    } else {
        // UID or name
        if let Ok(uid) = spec.parse::<u32>() {
            let pw = lookup_uid(uid);
            let gid = pw.as_ref().map(|p| p.gid).unwrap_or(uid);
            let name = pw.map(|p| p.name);
            Some(ResolvedUser { uid, gid, name })
        } else {
            // name → look up in /etc/passwd
            let pw = lookup_name(spec)?;
            Some(ResolvedUser {
                uid: pw.uid,
                gid: pw.gid,
                name: Some(pw.name),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_root() {
        let passwd =
            "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:Nobody:/:/usr/bin/nologin\n";
        let entry = parse_passwd_uid(passwd, 0).unwrap();
        assert_eq!(entry.name, "root");
        assert_eq!(entry.uid, 0);
        assert_eq!(entry.gid, 0);
        assert_eq!(entry.home, "/root");
        assert_eq!(entry.shell, "/bin/bash");
    }

    #[test]
    fn test_parse_nobody() {
        let passwd =
            "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:Nobody:/:/usr/bin/nologin\n";
        let entry = parse_passwd_uid(passwd, 65534).unwrap();
        assert_eq!(entry.name, "nobody");
        assert_eq!(entry.home, "/");
    }

    #[test]
    fn test_parse_not_found() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n";
        assert!(parse_passwd_uid(passwd, 999).is_none());
    }

    #[test]
    fn test_parse_ubuntu_user() {
        let passwd =
            "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n";
        let entry = parse_passwd_uid(passwd, 1000).unwrap();
        assert_eq!(entry.name, "ubuntu");
        assert_eq!(entry.gid, 1000);
        assert_eq!(entry.home, "/home/ubuntu");
    }

    #[test]
    fn test_parse_name() {
        let passwd =
            "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n";
        let entry = parse_passwd_name(passwd, "ubuntu").unwrap();
        assert_eq!(entry.uid, 1000);
        assert_eq!(entry.gid, 1000);
        assert!(parse_passwd_name(passwd, "nobody").is_none());
    }

    #[test]
    fn test_parse_group_name() {
        let group = "root:x:0:\nsudo:x:27:ubuntu,bob\ndocker:x:999:ubuntu\n";
        assert_eq!(parse_group_name(group, "sudo"), Some(27));
        assert_eq!(parse_group_name(group, "docker"), Some(999));
        assert_eq!(parse_group_name(group, "nonexistent"), None);
    }

    #[test]
    fn test_supplementary_groups() {
        let group = "root:x:0:\nsudo:x:27:ubuntu,bob\ndocker:x:999:ubuntu\nadm:x:4:bob\n";
        let groups = parse_supplementary_groups(group, "ubuntu");
        assert_eq!(groups, vec![27, 999]);

        let groups = parse_supplementary_groups(group, "bob");
        assert_eq!(groups, vec![27, 4]);

        let groups = parse_supplementary_groups(group, "nobody");
        assert!(groups.is_empty());
    }

    #[test]
    fn test_supplementary_groups_empty_members() {
        let group = "root:x:0:\nnogroup:x:65534:\n";
        let groups = parse_supplementary_groups(group, "root");
        assert!(groups.is_empty());
    }
}
