use core::ffi::CStr;
use std::{env, ffi::CString, io::SeekFrom, os::unix::io::RawFd, path::PathBuf};

use libc::{c_int, unlink, AT_FDCWD, FILE};
use mirrord_protocol::file::{
    OpenFileResponse, OpenOptionsInternal, ReadFileResponse, SeekFileResponse, WriteFileResponse,
    XstatFsResponse, XstatResponse,
};
use rand::distributions::{Alphanumeric, DistString};
use tokio::sync::oneshot;
use tracing::{error, trace};

use super::{filter::FILE_FILTER, hooks::FN_OPEN, *};
use crate::{
    common::blocking_send_hook_message,
    detour::{Bypass, Detour},
    error::{HookError, HookResult as Result},
    get_runtime, HookMessage,
};

/// 1 Megabyte. Large read requests can lead to timeouts.
const MAX_READ_SIZE: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RemoteFile {
    pub fd: u64,
    pub path: String,
}

impl RemoteFile {
    pub(crate) fn new(fd: u64, path: String) -> Self {
        Self { fd, path }
    }

    /// Sends a [`FileOperation::Open`] message, opening the file in the agent.
    #[tracing::instrument(level = "trace")]
    pub(crate) async fn remote_open(
        path: PathBuf,
        open_options: OpenOptionsInternal,
    ) -> Detour<OpenFileResponse> {
        let (file_channel_tx, file_channel_rx) = oneshot::channel();
        let requesting_file = Open {
            path,
            open_options,
            file_channel_tx,
        };

        blocking_send_file_message(FileOperation::Open(requesting_file)).await?;

        Detour::Success(file_channel_rx.await??)
    }

    /// Sends a [`FileOperation::Read`] message, reading the file in the agent.
    ///
    /// Blocking request and wait on already found remote_fd
    #[tracing::instrument(level = "trace")]
    pub(crate) async fn remote_read(remote_fd: u64, read_amount: u64) -> Detour<ReadFileResponse> {
        let (file_channel_tx, file_channel_rx) = oneshot::channel();

        // Limit read size because if we read too much it can lead to a timeout
        // Seems also that bincode doesn't do well with large buffers
        let read_amount = std::cmp::min(read_amount, MAX_READ_SIZE);
        let reading_file = Read {
            remote_fd,
            buffer_size: read_amount,
            start_from: 0,
            file_channel_tx,
        };

        blocking_send_file_message(FileOperation::Read(reading_file)).await?;

        Detour::Success(file_channel_rx.await??)
    }

    /// Sends a [`FileOperation::Close`] message, closing the file in the agent.
    #[tracing::instrument(level = "trace")]
    pub(crate) async fn remote_close(fd: u64) -> Result<()> {
        blocking_send_file_message(FileOperation::Close(Close { fd })).await
    }
}

impl Drop for RemoteFile {
    fn drop(&mut self) {
        // Warning: Don't log from here. This is called when self is removed from OPEN_FILES, so
        // during the whole execution of this function, OPEN_FILES is locked.
        // When emitting logs, sometimes a file `write` operation is required, in order for the
        // operation to complete. The write operation is hooked and at some point tries to lock
        // `OPEN_FILES`, which means the thread deadlocks with itself (we call
        // `OPEN_FILES.lock()?.remove()` and then while still locked, `OPEN_FILES.lock()` again)
        let rt = get_runtime();
        let _guard = rt.enter();
        let fd = self.fd;
        rt.spawn(async move {
            Self::remote_close(fd).await.expect(
                "mirrord failed to send close file message to main layer thread. Error: {err:?}",
            );
        });
    }
}

/// should_ignore(path: P, write: bool)
/// Checks if the file should be ignored, and returns a [`Bypass::IgnoredFile`] if it should.
macro_rules! should_ignore {
    ($path:expr, $write:expr) => {
        FILE_FILTER.get()?.continue_or_bypass_with(
            $path.to_str().unwrap_or_default(),
            $write,
            || Bypass::IgnoredFile($path.clone()),
        )?;
    };
}

/// Helper function that retrieves the `remote_fd` (which is generated by
/// `mirrord_agent::util::IndexAllocator`).
fn get_remote_fd(local_fd: RawFd) -> Detour<u64> {
    // don't add a trace here since it causes deadlocks in some cases.
    Detour::Success(
        OPEN_FILES
            .get(&local_fd)
            .map(|remote_file| remote_file.fd)
            // Bypass if we're not managing the relative part.
            .ok_or(Bypass::LocalFdNotFound(local_fd))?,
    )
}

/// Create temporary local file to get a valid local fd.
#[tracing::instrument(level = "trace")]
async fn create_local_fake_file(remote_fd: u64) -> Detour<RawFd> {
    let random_string = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
    let file_name = format!("{remote_fd}-{random_string}");
    let file_path = env::temp_dir().join(file_name);
    let file_c_string = CString::new(file_path.to_string_lossy().to_string())?;
    let file_path_ptr = file_c_string.as_ptr();
    let local_file_fd: RawFd = unsafe { FN_OPEN(file_path_ptr, O_RDONLY | O_CREAT) };
    if local_file_fd == -1 {
        // Close the remote file if creating a tmp local file failed and we have an invalid local fd
        close_remote_file_on_failure(remote_fd).await?;
        Detour::Error(HookError::LocalFileCreation(remote_fd))
    } else {
        unsafe { unlink(file_path_ptr) };
        Detour::Success(local_file_fd)
    }
}

/// Close the remote file if the call to [`libc::shm_open`] failed and we have an invalid local fd.
#[tracing::instrument(level = "trace")]
async fn close_remote_file_on_failure(fd: u64) -> Result<()> {
    error!("Creating a temporary local file resulted in an error, closing the file remotely!");
    RemoteFile::remote_close(fd).await
}

async fn blocking_send_file_message(message: FileOperation) -> Result<()> {
    blocking_send_hook_message(HookMessage::File(message)).await
}

/// Blocking wrapper around `libc::open` call.
///
/// **Bypassed** when trying to load system files, and files from the current working directory
/// (which is different anyways when running in `-agent` context).
///
/// When called for a valid file, it blocks and sends an open file request to be handled by
/// `mirrord-agent`, and waits until it receives an open file response.
///
/// [`open`] is also used by other _open-ish_ functions, and it takes care of **creating** the
/// _local_ and _remote_ file association, plus **inserting** it into the storage for
/// [`OPEN_FILES`].
#[tracing::instrument(level = "trace")]
pub(crate) async fn open(
    path: Detour<PathBuf>,
    open_options: OpenOptionsInternal,
) -> Detour<RawFd> {
    let path = path?;

    if path.is_relative() {
        // Calls with non absolute paths are sent to libc::open.
        Detour::Bypass(Bypass::RelativePath(path.clone()))?
    };

    should_ignore!(path, open_options.is_write());

    let OpenFileResponse { fd: remote_fd } =
        RemoteFile::remote_open(path.clone(), open_options).await?;
    // TODO: Need a way to say "open a directory", right now `is_dir` always returns false.
    // This requires having a fake directory name (`/fake`, for example), instead of just
    // converting the fd to a string.
    let local_file_fd = create_local_fake_file(remote_fd).await?;

    OPEN_FILES.insert(
        local_file_fd,
        Arc::new(RemoteFile::new(remote_fd, path.display().to_string())),
    );

    Detour::Success(local_file_fd)
}

#[tracing::instrument(level = "trace")]
pub(crate) fn fdopen(fd: RawFd, rawish_mode: Option<&CStr>) -> Detour<*mut FILE> {
    let _open_options: OpenOptionsInternal = rawish_mode
        .map(CStr::to_str)
        .transpose()
        .map_err(|fail| {
            warn!(
                "Failed converting `rawish_mode` from `CStr` with {:#?}",
                fail
            );

            Bypass::CStrConversion
        })?
        .map(String::from)
        .map(OpenOptionsInternalExt::from_mode)
        .unwrap_or_default();

    trace!("fdopen -> open_options {_open_options:#?}");

    // TODO: Check that the constraint: remote file must have the same mode stuff that is passed
    // here.
    let result = OPEN_FILES
        .get(&fd)
        .ok_or(Bypass::LocalFdNotFound(fd))
        .map(|_| fd as *const RawFd as *mut _)?;

    Detour::Success(result)
}

/// creates a directory stream for the `remote_fd` in the agent
#[tracing::instrument(level = "trace")]
pub(crate) async fn fdopendir(fd: RawFd) -> Detour<usize> {
    // usize == ptr size
    // we don't return a pointer to an address that contains DIR

    let remote_file_fd = OPEN_FILES.get(&fd).ok_or(Bypass::LocalFdNotFound(fd))?.fd;

    let (dir_channel_tx, dir_channel_rx) = oneshot::channel();

    let open_dir_request = FdOpenDir {
        remote_fd: remote_file_fd,
        dir_channel_tx,
    };

    blocking_send_file_message(FileOperation::FdOpenDir(open_dir_request)).await?;

    let OpenDirResponse { fd: remote_dir_fd } = dir_channel_rx.await??;

    let local_dir_fd = create_local_fake_file(remote_dir_fd).await?;
    OPEN_DIRS.insert(local_dir_fd as usize, remote_dir_fd);

    // According to docs, when using fdopendir, the fd is now managed by OS - i.e closed
    OPEN_FILES.remove(&fd);

    Detour::Success(local_dir_fd as usize)
}

// fetches the current entry in the directory stream created by `fdopendir`
#[tracing::instrument(level = "trace")]
pub(crate) async fn readdir_r(dir_stream: usize) -> Detour<Option<DirEntryInternal>> {
    let remote_fd = *OPEN_DIRS
        .get(&dir_stream)
        .ok_or(Bypass::LocalDirStreamNotFound(dir_stream))?;

    let (dir_channel_tx, dir_channel_rx) = oneshot::channel();

    let requesting_dir = ReadDir {
        remote_fd,
        dir_channel_tx,
    };

    blocking_send_file_message(FileOperation::ReadDir(requesting_dir)).await?;

    let ReadDirResponse { direntry } = dir_channel_rx.await??;
    Detour::Success(direntry)
}

#[tracing::instrument(level = "trace")]
pub(crate) async fn closedir(dir_stream: usize) -> Detour<c_int> {
    let remote_fd = *OPEN_DIRS
        .get(&dir_stream)
        .ok_or(Bypass::LocalDirStreamNotFound(dir_stream))?;

    let requesting_dir = CloseDir { fd: remote_fd };

    blocking_send_file_message(FileOperation::CloseDir(requesting_dir)).await?;

    Detour::Success(0)
}

#[tracing::instrument(level = "trace")]
pub(crate) async fn openat(
    fd: RawFd,
    path: Detour<PathBuf>,
    open_options: OpenOptionsInternal,
) -> Detour<RawFd> {
    let path = path?;

    // `openat` behaves the same as `open` when the path is absolute. When called with AT_FDCWD, the
    // call is propagated to `open`.
    if path.is_absolute() || fd == AT_FDCWD {
        open(Detour::Success(path), open_options).await
    } else {
        // Relative path requires special handling, we must identify the relative part (relative to
        // what).
        let remote_fd = get_remote_fd(fd)?;

        let (file_channel_tx, file_channel_rx) = oneshot::channel();

        let requesting_file = OpenRelative {
            relative_fd: remote_fd,
            path: path.clone(),
            open_options,
            file_channel_tx,
        };

        blocking_send_file_message(FileOperation::OpenRelative(requesting_file)).await?;

        let OpenFileResponse { fd: remote_fd } = file_channel_rx.await??;
        let local_file_fd = create_local_fake_file(remote_fd).await?;

        OPEN_FILES.insert(
            local_file_fd,
            Arc::new(RemoteFile::new(remote_fd, path.display().to_string())),
        );

        Detour::Success(local_file_fd)
    }
}

/// Blocking wrapper around [`libc::read`] call.
///
/// **Bypassed** when trying to load system files, and files from the current working directory, see
/// `open`.
pub(crate) fn read(local_fd: RawFd, read_amount: u64) -> Detour<ReadFileResponse> {
    get_remote_fd(local_fd).and_then(|remote_fd| {
        get_runtime().block_on(RemoteFile::remote_read(remote_fd, read_amount))
    })
}

#[tracing::instrument(level = "trace")]
pub(crate) async fn pread(
    local_fd: RawFd,
    buffer_size: u64,
    offset: u64,
) -> Detour<ReadFileResponse> {
    // We're only interested in files that are paired with mirrord-agent.
    let remote_fd = get_remote_fd(local_fd)?;

    let (file_channel_tx, file_channel_rx) = oneshot::channel();

    let reading_file = Read {
        remote_fd,
        buffer_size: buffer_size as _,
        start_from: offset,
        file_channel_tx,
    };

    blocking_send_file_message(FileOperation::ReadLimited(reading_file)).await?;

    Detour::Success(file_channel_rx.await??)
}

pub(crate) async fn pwrite(
    local_fd: RawFd,
    buffer: &[u8],
    offset: u64,
) -> Detour<WriteFileResponse> {
    let remote_fd = get_remote_fd(local_fd)?;

    let (file_channel_tx, file_channel_rx) = oneshot::channel();

    let writing_file = Write {
        remote_fd,
        write_bytes: buffer.to_vec(),
        start_from: offset,
        file_channel_tx,
    };

    blocking_send_file_message(FileOperation::WriteLimited(writing_file)).await?;

    Detour::Success(file_channel_rx.await??)
}

#[tracing::instrument(level = "trace")]
pub(crate) async fn lseek(local_fd: RawFd, offset: i64, whence: i32) -> Detour<u64> {
    let remote_fd = get_remote_fd(local_fd)?;

    let seek_from = match whence {
        libc::SEEK_SET => SeekFrom::Start(offset as u64),
        libc::SEEK_CUR => SeekFrom::Current(offset),
        libc::SEEK_END => SeekFrom::End(offset),
        invalid => {
            warn!(
                "lseek -> potential invalid value {:#?} for whence {:#?}",
                invalid, whence
            );
            return Detour::Bypass(Bypass::CStrConversion);
        }
    };

    let (file_channel_tx, file_channel_rx) = oneshot::channel();

    let seeking_file = Seek {
        remote_fd,
        seek_from,
        file_channel_tx,
    };

    blocking_send_file_message(FileOperation::Seek(seeking_file)).await?;

    let SeekFileResponse { result_offset } = file_channel_rx.await??;
    Detour::Success(result_offset)
}

pub(crate) async fn write(local_fd: RawFd, write_bytes: Option<Vec<u8>>) -> Detour<isize> {
    let remote_fd = get_remote_fd(local_fd)?;

    let (file_channel_tx, file_channel_rx) = oneshot::channel();

    let writing_file = Write {
        remote_fd,
        write_bytes: write_bytes.ok_or(Bypass::EmptyBuffer)?,
        start_from: 0,
        file_channel_tx,
    };

    blocking_send_file_message(FileOperation::Write(writing_file)).await?;

    let WriteFileResponse { written_amount } = file_channel_rx.await??;
    Detour::Success(written_amount.try_into()?)
}

#[tracing::instrument(level = "trace")]
pub(crate) async fn access(path: Detour<PathBuf>, mode: u8) -> Detour<c_int> {
    let path = path?;

    should_ignore!(path, false);

    if path.is_relative() {
        // Calls with non absolute paths are sent to libc::open.
        Detour::Bypass(Bypass::RelativePath(path.clone()))?
    };

    let (file_channel_tx, file_channel_rx) = oneshot::channel();

    let access = Access {
        path,
        mode,
        file_channel_tx,
    };

    blocking_send_file_message(FileOperation::Access(access)).await?;

    file_channel_rx.await??;

    Detour::Success(0)
}

/// General stat function that can be used for lstat, fstat, stat and fstatat.
/// Note: We treat cases of `AT_SYMLINK_NOFOLLOW_ANY` as `AT_SYMLINK_NOFOLLOW` because even Go does
/// that.
/// rawish_path is Option<Option<&CStr>> because we need to differentiate between null pointer
/// and non existing argument (For error handling)
#[tracing::instrument(level = "trace")]
pub(crate) async fn xstat(
    rawish_path: Option<Detour<PathBuf>>,
    fd: Option<RawFd>,
    follow_symlink: bool,
) -> Detour<XstatResponse> {
    // Can't use map because we need to propagate captured error
    let (path, fd) = match (rawish_path, fd) {
        // fstatat
        (Some(path), Some(fd)) => {
            let path = path?;
            let fd = {
                if fd == AT_FDCWD {
                    if path.is_relative() {
                        // Calls with non absolute paths are sent to libc::fstatat.
                        return Detour::Bypass(Bypass::RelativePath(path));
                    } else {
                        should_ignore!(path, false);
                        None
                    }
                } else {
                    Some(get_remote_fd(fd)?)
                }
            };
            (Some(path), fd)
        }
        // lstat/stat
        (Some(path), None) => {
            let path = path?;
            if path.is_relative() {
                // Calls with non absolute paths are sent to libc::open.
                return Detour::Bypass(Bypass::RelativePath(path));
            }
            should_ignore!(path, false);
            (Some(path), None)
        }
        // fstat
        (None, Some(fd)) => (None, Some(get_remote_fd(fd)?)),
        // can't happen
        (None, None) => return Detour::Error(HookError::NullPointer),
    };

    let (file_channel_tx, file_channel_rx) = oneshot::channel();

    let lstat = Xstat {
        fd,
        path,
        follow_symlink,
        file_channel_tx,
    };

    blocking_send_file_message(FileOperation::Xstat(lstat)).await?;

    Detour::Success(file_channel_rx.await??)
}

#[tracing::instrument(level = "trace")]
pub(crate) async fn xstatfs(fd: RawFd) -> Detour<XstatFsResponse> {
    let fd = get_remote_fd(fd)?;

    let (fs_channel_tx, fs_channel_rx) = oneshot::channel();

    let lstatfs = XstatFs { fd, fs_channel_tx };

    blocking_send_file_message(FileOperation::XstatFs(lstatfs)).await?;

    Detour::Success(fs_channel_rx.await??)
}

#[cfg(target_os = "linux")]
#[tracing::instrument(level = "trace")]
pub(crate) async fn getdents64(fd: RawFd, buffer_size: u64) -> Detour<GetDEnts64Response> {
    // We're only interested in files that are paired with mirrord-agent.
    let remote_fd = get_remote_fd(fd)?;

    let (dents_tx, dents_rx) = oneshot::channel();

    let getdents64_message = GetDEnts64 {
        remote_fd,
        buffer_size,
        dents_tx,
    };

    blocking_send_file_message(FileOperation::GetDEnts64(getdents64_message)).await?;

    Detour::Success(dents_rx.blocking_recv()??)
}
