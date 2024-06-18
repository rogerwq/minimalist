use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::path::{Path, PathBuf};

use ssh2::Session;
use thiserror::Error as ErrorProcMacro;

#[derive(Debug, ErrorProcMacro)]
enum Error {
    #[error("Tcp stream connection to {0}:{1} error: {2}")]
    TcpStreamConnect(IpAddr, u16, String),
    #[error("Session initializing error: {0}")]
    SessionNew(String),
    #[error("Session handshake error: {0}")]
    SessionHandshake(String),
    #[error("Session auth user {0} with private key file {1} error: {2}")]
    SessionUserAuth(String, PathBuf, String),
    #[error("Create remote file {0} of size {1} error: {2}")]
    CreateRemoteFile(PathBuf, u64, String),
    #[error("Write remote file {0} error: {1}")]
    WriteRemoteFile(PathBuf, String),
}

/// Establishes a new SSH session using the provided IP address, port, username, and private key file path.
///
/// # Arguments
///
/// * `ip` - The IP address of the remote host to connect to.
/// * `port` - The port number on the remote host to connect to.
/// * `username` - The username to authenticate with on the remote host.
/// * `privatekey` - The path to the private key file used for authentication.
///
/// # Returns
///
/// This function returns an `anyhow::Result<Session>`. On success, it contains a new SSH session. On failure, it returns an error detailing what went wrong.
///
/// # Errors
///
/// This function will return an error in the following cases:
/// * If the TCP connection to the specified `ip` and `port` fails.
/// * If creating a new SSH session fails.
/// * If the handshake process with the SSH server fails.
/// * If the user authentication with the provided `username` and `privatekey` fails.
///
/// # Examples
///
/// ```rust
/// use std::net::IpAddr;
/// use std::path::Path;
/// use std::env;
/// use minimalist::ssh2::create_session;
///
/// fn main() -> anyhow::Result<()> {
///     let ip: IpAddr = "127.0.0.1".parse().unwrap();
///     let port: u16 = 22;
///     let username = env::var("LOCAL_SSH_USERNAME").unwrap();
///     let privatekey = home::home_dir().unwrap().join(".ssh").join("id_rsa");
///
///     let session = create_session(ip, port, &username, privatekey.as_path())?;
///     // Use the session
///
///     Ok(())
/// }
/// ```
///
/// # Panics
///
/// This function will panic if the authentication is not successful after the `userauth_pubkey_file` call.
///
pub fn create_session(ip: IpAddr, port: u16, username: &str, privatekey: &Path) -> anyhow::Result<Session> {
    let tcp = TcpStream::connect(format!("{ip}:{port}"))
        .map_err(|e| Error::TcpStreamConnect(ip, port, e.to_string()))?;
    let mut sess = Session::new()
        .map_err(|e| Error::SessionNew(e.to_string()))?;
    sess.set_tcp_stream(tcp);
    sess.handshake()
        .map_err(|e| Error::SessionHandshake(e.to_string()))?;
    sess.userauth_pubkey_file(username, None, privatekey, None)
        .map_err(|e| Error::SessionUserAuth(username.to_string(), privatekey.into(), e.to_string()))?;
    assert!(sess.authenticated());
    Ok(sess)
}

/// Writes the specified content to a file on the remote host using the established SSH session.
///
/// # Arguments
///
/// * `sess` - An active SSH session through which the file will be written.
/// * `content` - The content to be written to the remote file.
/// * `remote_file` - The path on the remote host where the file will be created or overwritten.
///
/// # Returns
///
/// This function returns an `anyhow::Result<()>`. On success, it returns `Ok(())`. On failure, it returns an error detailing what went wrong.
///
/// # Errors
///
/// This function will return an error in the following cases:
/// * If the creation of the remote file fails.
/// * If writing to the remote file fails.
/// * If any of the EOF or close operations on the SCP channel fail.
///
/// # Examples
///
/// ```rust
/// use std::net::IpAddr;
/// use std::path::Path;
/// use anyhow::Result;
/// use ssh2::Session;
/// use std::env;
/// use minimalist::ssh2::*;
///
/// fn main() -> Result<()> {
///     let ip: IpAddr = "127.0.0.1".parse().unwrap();
///     let port: u16 = 22;
///     let username = env::var("LOCAL_SSH_USERNAME").unwrap();
///     let privatekey = home::home_dir().unwrap().join(".ssh").join("id_rsa");
///     let remote_file = Path::new("remote_file.txt");
///     let content = "This is the file content";
///
///     let sess = create_session(ip, port, &username, &privatekey)?;
///     write_file(&sess, content, remote_file)?;
///
///     Ok(())
/// }
/// ```
///
/// # Panics
///
/// This function does not explicitly panic.
pub fn write_file(sess: &Session, content: &str, remote_file: &Path) -> anyhow::Result<()> {
    let mut write_channel = sess.scp_send(remote_file, 0o644, content.len() as u64, None)
        .map_err(|e| Error::CreateRemoteFile(remote_file.into(), content.len() as u64, e.to_string()))?;
    write_channel.write_all(content.as_bytes())
        .map_err(|e| Error::WriteRemoteFile(remote_file.into(), e.to_string()))?;
    write_channel.send_eof()?;
    write_channel.wait_eof()?;
    write_channel.close()?;
    write_channel.wait_close()?;
    Ok(())
}

pub fn run_commands(sess: &Session, commands: &[&str]) -> String {
    let mut channel = sess.channel_session().unwrap();
    let joined_comand = commands.join(";");
    channel.exec(&joined_comand).unwrap();
    let mut s = String::new();
    channel.read_to_string(&mut s).unwrap();
    channel.wait_close().unwrap();
    s
}
