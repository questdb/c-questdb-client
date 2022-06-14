use socket2::SockAddr;
use dns_lookup::{AddrInfoHints, AddrInfo, AddrInfoIter, LookupError};

#[cfg(unix)]
use libc::{AF_INET, SOCK_STREAM};

#[cfg(windows)]
use winapi::shared::ws2def::{AF_INET, SOCK_STREAM};

fn map_getaddrinfo_result(
    dest: &str,
    result: Result<AddrInfoIter, LookupError>) -> super::Result<SockAddr>
{
    match result {
        Ok(mut addrs) => {
            let addr: AddrInfo = addrs.next().unwrap().map_err(
                |io_err| super::Error {
                    code: super::ErrorCode::CouldNotResolveAddr,
                    msg: format!("Could not resolve {:?}: {}", dest, io_err)
                })?;
            Ok(addr.sockaddr.into())
        },
        Err(lookup_err) => {
            let io_err: std::io::Error = lookup_err.into();
            Err(super::Error{
                code: super::ErrorCode::CouldNotResolveAddr,
                msg: format!("Could not resolve {:?}: {}", dest, io_err)})
        }
    }
}

pub(super) fn resolve_host(host: &str) -> super::Result<SockAddr> {
    let hints = AddrInfoHints {
        socktype: SOCK_STREAM,
        address: AF_INET,
        ..AddrInfoHints::default()};
    map_getaddrinfo_result(
        host,
        dns_lookup::getaddrinfo(Some(host), None, Some(hints)))
}

pub(super) fn resolve_host_port(host: &str, port: &str) -> super::Result<SockAddr> {
    let hints = AddrInfoHints {
        socktype: SOCK_STREAM,
        address: AF_INET,
        ..AddrInfoHints::default()};
    let host_port = format!("{}:{}", host, port);
    map_getaddrinfo_result(
        &host_port,
        dns_lookup::getaddrinfo(Some(host), Some(port), Some(hints)))
}