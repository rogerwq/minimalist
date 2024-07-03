use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::path::{Path, PathBuf};

pub use ssh2::Session;
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
    #[error("Create remote file {0} error: {1}")]
    CreateRemoteFile(PathBuf, String),
    #[error("Write remote file {0} error: {1}")]
    WriteRemoteFile(PathBuf, String),
    #[error("Execute commands {0} error: {1}")]
    ExecCommands(String, String),
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
/// use minimalist::ssh2::*;
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
/// use ssh2::Session;
/// use std::env;
/// use minimalist::ssh2::*;
///
/// fn main() -> anyhow::Result<()> {
///     let ip: IpAddr = "127.0.0.1".parse().unwrap();
///     let port: u16 = 22;
///     let username = env::var("LOCAL_SSH_USERNAME").unwrap();
///     let privatekey = home::home_dir().unwrap().join(".ssh").join("id_rsa");
///     let remote_file = Path::new("remote_file.txt");
///     let content = "This is the file content";
///
///     let sess = create_session(ip, port, &username, &privatekey)?;
///     write_file(&sess, content, remote_file)?;
///     run_commands(&sess, &["rm remote_file.txt"])?;
///
///     Ok(())
/// }
/// ```
///
/// # Panics
///
/// This function does not explicitly panic.
pub fn write_file(sess: &Session, content: &str, remote_file: &Path) -> anyhow::Result<()> {
    let mut channel = sess.scp_send(remote_file, 0o644, content.len() as u64, None)
        .map_err(|e| Error::CreateRemoteFile(remote_file.into(), e.to_string()))?;
    channel.write_all(content.as_bytes())
        .map_err(|e| Error::WriteRemoteFile(remote_file.into(), e.to_string()))?;
    channel.send_eof()?;
    channel.wait_eof()?;
    channel.close()?;
    channel.wait_close()?;
    Ok(())
}

/// Reads the contents of a remote file over an SSH session and returns it as a string.
///
/// # Arguments
///
/// * `sess` - A reference to an established SSH `Session`.
/// * `remote_file` - A reference to a `Path` representing the location of the remote file to be read.
///
/// # Returns
///
/// * `Ok(String)` - The contents of the remote file if it is read successfully.
/// * `Err(anyhow::Error)` - An error containing details if any step of the read process fails.
///
/// # Errors
///
/// This function will return an error in the following cases:
///
/// * If there is an issue initiating the SCP receive session.
/// * If there is an issue reading the data from the remote file.
///
/// The error returned will include context about the specific step that failed.
///
/// # Example
///
/// ```
/// use std::net::IpAddr;
/// use std::path::Path;
/// use ssh2::Session;
/// use std::env;
/// use minimalist::ssh2::*;
///
/// fn main() -> anyhow::Result<()> {
///     let ip: IpAddr = "127.0.0.1".parse().unwrap();
///     let port: u16 = 22;
///     let username = env::var("LOCAL_SSH_USERNAME").unwrap();
///     let privatekey = home::home_dir().unwrap().join(".ssh").join("id_rsa");
///     let sess = create_session(ip, port, &username, &privatekey)?;
///
///     let remote_file = Path::new("remote_file.txt");
///     let content_written = "This is the file content";
///     write_file(&sess, content_written, remote_file)?;
///
///     let content_read = read_file(&sess, &remote_file)?;
///     assert_eq!(content_written, content_read);
///     run_commands(&sess, &["rm remote_file.txt"])?;
///
///     Ok(())
/// }
/// ```
///
/// # Dependencies
///
/// This function depends on the `ssh2` crate for managing the SSH session and SCP channel, and `anyhow` crate for error handling.
///
/// # Note
///
/// * Make sure that the `Session` object is properly authenticated before calling this function.
/// * The function reads the entire contents of the remote file into a `String`.
/// * Ensure that the remote file is accessible and readable by the SSH user.
pub fn read_file(sess: &Session, remote_file: &Path) -> anyhow::Result<String> {
    let (mut channel, _) = sess.scp_recv(remote_file)
        .map_err(|e| Error::CreateRemoteFile(remote_file.into(), e.to_string()))?;
    let mut data = String::new();
    channel.read_to_string(&mut data)?;
    Ok(data)
}

/// Executes a sequence of commands on a remote session and returns the combined output.
///
/// # Arguments
///
/// * `sess` - A reference to an established SSH `Session`.
/// * `commands` - A slice of string slices representing the commands to be executed sequentially.
///
/// # Returns
///
/// * `Ok(String)` - The combined standard output and standard error of the executed commands if they run successfully.
/// * `Err(anyhow::Error)` - An error containing details if any step of the execution fails.
///
/// # Errors
///
/// This function will return an error in the following cases:
///
/// * If there is an issue creating the channel session.
/// * If there is an issue executing the commands.
/// * If there is an issue reading the output from the remote session.
/// * If there is an issue closing the channel.
///
/// The error returned will include context about the specific step that failed.
///
/// # Example
///
/// ```
/// use std::net::{IpAddr, TcpStream};
/// use std::env;
/// use ssh2::Session;
/// use minimalist::ssh2::*;
///
/// fn main() -> anyhow::Result<()> {
///     let ip: IpAddr = "127.0.0.1".parse().unwrap();
///     let port: u16 = 22;
///     let username = env::var("LOCAL_SSH_USERNAME").unwrap();
///     let privatekey = home::home_dir().unwrap().join(".ssh").join("id_rsa");
///     let sess = create_session(ip, port, &username, &privatekey)?;
///
///     let commands = ["echo 'Hello, world!'", "uname -a"];
///     let output = run_commands(&sess, &commands)?;
///     println!("{}", output);
///
///     Ok(())
/// }
/// ```
///
/// # Dependencies
///
/// This function depends on the `ssh2` crate for managing the SSH session and channels, and `anyhow` crate for error handling.
///
/// # Note
///
/// * Make sure that the `Session` object is properly authenticated before calling this function.
/// * The commands are joined using a semicolon (`;`), which means they will be executed in sequence within a single shell session.
/// * The function captures both standard output and standard error combined in the returned string.
pub fn run_commands(sess: &Session, commands: &[&str]) -> anyhow::Result<String> {
    let mut channel = sess.channel_session()?;
    let joined_comand = commands.join(";");
    channel.exec(&joined_comand)
        .map_err(|e| Error::ExecCommands(joined_comand, e.to_string()))?;
    let mut s = String::new();
    channel.read_to_string(&mut s)?;
    channel.wait_close()?;
    Ok(s)
}
