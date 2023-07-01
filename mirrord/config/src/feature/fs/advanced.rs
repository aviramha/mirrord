use mirrord_analytics::{CollectAnalytics, AnalyticValue};
use mirrord_config_derive::MirrordConfig;
use schemars::JsonSchema;

use super::{FsModeConfig, FsUserConfig};
use crate::{
    config::{from_env::FromEnv, source::MirrordConfigSource, ConfigError},
    util::{MirrordToggleableConfig, VecOrSingle},
};

// TODO(alex): We could turn this derive macro (`MirrordConfig`) into an attribute version, which
// would allow us to "capture" the `derive` statement, making it possible to implement the same for
// whatever is generated by `map_to`.

/// Allows the user to specify the default behavior for file operations:
///
/// 1. `"read"` - Read from the remote file system (default)
/// 2. `"write"` - Read/Write from the remote file system.
/// 3. `"local"` - Read from the local file system.
/// 5. `"disable"` - Disable file operations.
///
/// Besides the default behavior, the user can specify behavior for specific regex patterns.
/// Case insensitive.
///
/// 1. `"read_write"` - List of patterns that should be read/write remotely.
/// 2. `"read_only"` - List of patterns that should be read only remotely.
/// 3. `"local"` - List of patterns that should be read locally.
///
/// The logic for choosing the behavior is as follows:
///
/// 1. Check if one of the patterns match the file path, do the corresponding action. There's
/// no specified order if two lists match the same path, we will use the first one (and we
/// do not guarantee what is first).
///
/// **Warning**: Specifying the same path in two lists is unsupported and can lead to undefined
/// behaviour.
///
/// 2. Check our "special list" - we have an internal at compile time list
/// for different behavior based on patterns to provide better UX.
///
/// 3. If none of the above match, use the default behavior (mode).
///
/// For more information, check the file operations
/// [technical reference](https://mirrord.dev/docs/reference/fileops/).
///
/// ```json
/// {
///   "feature": {
///     "fs": {
///       "mode": "write",
///       "read_write": ".+\.json" ,
///       "read_only": [ ".+\.yaml", ".+important-file\.txt" ],
///       "local": [ ".+\.js", ".+\.mjs" ]
///     }
///   }
/// }
/// ```
#[derive(MirrordConfig, Default, Clone, PartialEq, Eq, Debug)]
#[config(
    map_to = "AdvancedFsUserConfig",
    derive = "PartialEq,Eq,JsonSchema",
    generator = "FsUserConfig"
)]
pub struct FsConfig {
    /// ### feature.fs.mode {#feature-fs-mode}
    #[config(nested)]
    pub mode: FsModeConfig,

    /// ### feature.fs.read_write {#feature-fs-read_write}
    ///
    /// Specify file path patterns that if matched will be read and written to the remote.
    #[config(env = "MIRRORD_FILE_READ_WRITE_PATTERN")]
    pub read_write: Option<VecOrSingle<String>>,

    /// ### feature.fs.read_only {#feature-fs-read_only}
    ///
    /// Specify file path patterns that if matched will be read from the remote.
    /// if file matching the pattern is opened for writing or read/write it will be opened locally.
    pub read_only: Option<VecOrSingle<String>>,

    /// ### feature.fs.local {#feature-fs-local}
    ///
    /// Specify file path patterns that if matched will be opened locally.
    #[config(env = "MIRRORD_FILE_LOCAL_PATTERN")]
    pub local: Option<VecOrSingle<String>>,
}

impl MirrordToggleableConfig for AdvancedFsUserConfig {
    fn disabled_config() -> Result<Self::Generated, ConfigError> {
        let mode = FsModeConfig::disabled_config()?;
        let read_write = FromEnv::new("MIRRORD_FILE_READ_WRITE_PATTERN")
            .source_value()
            .transpose()?;
        let read_only = FromEnv::new("MIRRORD_FILE_READ_ONLY_PATTERN")
            .source_value()
            .transpose()?;
        let local = FromEnv::new("MIRRORD_FILE_LOCAL_PATTERN")
            .source_value()
            .transpose()?;

        Ok(Self::Generated {
            mode,
            read_write,
            read_only,
            local,
        })
    }
}

impl FsConfig {
    pub fn is_read(&self) -> bool {
        self.mode.is_read()
    }

    pub fn is_write(&self) -> bool {
        self.mode.is_write()
    }

    /// Checks if fs operations are active
    pub fn is_active(&self) -> bool {
        !matches!(self.mode, FsModeConfig::Local)
    }
}

impl From<FsModeConfig> for AnalyticValue {
    fn from(mode: FsModeConfig) -> Self {
        match mode {
            FsModeConfig::Local => Self::Number(0),
            FsModeConfig::LocalWithOverrides => Self::Number(1),
            FsModeConfig::Read => Self::Number(2),
            FsModeConfig::Write => Self::Number(3),
        }
    }
}

impl CollectAnalytics for FsConfig {
    fn collect_analytics(&self, analytics: &mut mirrord_analytics::Analytics) {
        analytics.add("mode", self.mode)
    }
}
#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::config::MirrordConfig;

    #[rstest]
    fn advanced_fs_config_default() {
        let expect = FsConfig {
            mode: FsModeConfig::Read,
            ..Default::default()
        };

        let fs_config = AdvancedFsUserConfig::default().generate_config().unwrap();

        assert_eq!(fs_config, expect);
    }
}
