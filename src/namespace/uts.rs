//! UTS namespace — hostname isolation.

use crate::error::{Error, Result};

/// Set the hostname inside the UTS namespace.
pub fn set_hostname(hostname: &str) -> Result<()> {
    nix::unistd::sethostname(hostname).map_err(Error::SetHostname)
}

/// Set the domainname inside the UTS namespace.
pub fn set_domainname(domainname: &str) -> Result<()> {
    // setdomainname is not wrapped by nix, use libc directly
    let ret = unsafe {
        libc::setdomainname(
            domainname.as_ptr() as *const libc::c_char,
            domainname.len(),
        )
    };
    if ret != 0 {
        return Err(Error::SetHostname(nix::Error::last()));
    }
    Ok(())
}
