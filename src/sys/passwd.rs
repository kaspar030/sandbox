//! Parse /etc/passwd to resolve UID → username, home directory, shell.

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
}
