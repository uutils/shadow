// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore newuidmap newgidmap subuid subgid pidfd openat fstat setgroups rootless podman

//! `newuidmap` and `newgidmap` — set the ID mappings of a user namespace.
//!
//! Drop-in replacements for the shadow-utils helpers of the same names, which
//! are what makes rootless containers possible: an unprivileged user may map
//! only their own ID into a namespace they create, and these setuid helpers
//! extend that to the ranges the administrator granted them in `/etc/subuid`
//! and `/etc/subgid`. Podman and rootless Docker call them for every
//! container they start.
//!
//! The two are one program with a selector; `newgidmap` lives in its own
//! crate and names the selector.
//!
//! What the kernel requires of the write is in `user_namespaces(7)`. What the
//! helper must check before writing was established by running the GNU
//! helper: the caller must own the target process, every requested range must
//! sit inside a range granted to the caller, and root is exempt from neither.

use std::fmt;
use std::fmt::Write as _;
use std::os::fd::{AsFd as _, OwnedFd, RawFd};

use clap::{Arg, Command};

use shadow_core::subid::SubIdEntry;

use uucore::error::{UError, UResult};

mod options {
    pub const ARGS: &str = "args";
}

/// `user_namespaces(7)`: "Since Linux 4.16, the limit is 340 lines."
const MAX_LINES: usize = 340;

/// Which map is being written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Uid,
    Gid,
}

impl Tool {
    fn name(self) -> &'static str {
        match self {
            Self::Uid => "newuidmap",
            Self::Gid => "newgidmap",
        }
    }

    /// The kind of ID, as the messages and the man pages spell it.
    fn id(self) -> &'static str {
        match self {
            Self::Uid => "uid",
            Self::Gid => "gid",
        }
    }

    fn map_file(self) -> &'static str {
        match self {
            Self::Uid => "uid_map",
            Self::Gid => "gid_map",
        }
    }

    fn subid_path(self, root: &shadow_core::sysroot::SysRoot) -> std::path::PathBuf {
        match self {
            Self::Uid => root.subuid_path(),
            Self::Gid => root.subgid_path(),
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Every failure exits 1, as the GNU helpers do; the variants keep the
/// messages apart.
#[derive(Debug)]
enum MapError {
    /// The command line is malformed.
    Usage(String),
    /// The target process cannot be opened or is not the caller's.
    Target(String),
    /// A range is not granted to the caller, or the set of ranges is invalid.
    NotAllowed(String),
    /// The kernel refused the write.
    Write(String),
}

impl fmt::Display for MapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(m) | Self::Target(m) | Self::NotAllowed(m) | Self::Write(m) => {
                f.write_str(m)
            }
        }
    }
}

impl std::error::Error for MapError {}

impl UError for MapError {
    fn code(&self) -> i32 {
        match self {
            Self::Usage(_) | Self::Target(_) | Self::NotAllowed(_) | Self::Write(_) => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// The command line
// ---------------------------------------------------------------------------

/// Where to find the target process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Pid(u32),
    /// `fd:N`: a descriptor the caller already holds open on `/proc/<pid>`,
    /// which is how a caller makes sure the pid has not been recycled between
    /// its own checks and this program's.
    Fd(RawFd),
}

/// One `inside outside count` triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mapping {
    inside: u32,
    outside: u32,
    count: u32,
}

impl Mapping {
    fn outside_end(self) -> u64 {
        u64::from(self.outside) + u64::from(self.count)
    }
    fn inside_end(self) -> u64 {
        u64::from(self.inside) + u64::from(self.count)
    }
}

/// A decimal number and nothing else: no sign, no space, no suffix.
fn parse_u32(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn usage(tool: Tool) -> MapError {
    MapError::Usage(format!(
        "usage: {} [<pid>|fd:<pidfd>] <{id}> <lower{id}> <count> [ <{id}> <lower{id}> <count> ] ...",
        tool.name(),
        id = tool.id()
    ))
}

/// Split the operands into the target and the mappings.
fn parse_args(tool: Tool, args: &[String]) -> Result<(Target, Vec<Mapping>), MapError> {
    let Some(first) = args.first() else {
        return Err(usage(tool));
    };
    let target = if let Some(fd) = first.strip_prefix("fd:") {
        Target::Fd(
            parse_u32(fd)
                .and_then(|n| RawFd::try_from(n).ok())
                .ok_or_else(|| usage(tool))?,
        )
    } else {
        Target::Pid(parse_u32(first).ok_or_else(|| usage(tool))?)
    };

    let rest = &args[1..];
    if rest.is_empty() || !rest.len().is_multiple_of(3) {
        // The GNU wording, which reports the count that did not divide.
        return Err(MapError::Usage(format!(
            "ranges: {} is wrong for argc: {}",
            rest.len().div_ceil(3),
            args.len()
        )));
    }
    let mut mappings = Vec::with_capacity(rest.len() / 3);
    for [inside, outside, count] in rest.as_chunks::<3>().0 {
        let inside = parse_u32(inside).ok_or_else(|| usage(tool))?;
        let outside = parse_u32(outside).ok_or_else(|| usage(tool))?;
        // Not a number at all is a usage error; a number that is not a
        // positive count is reported the way the GNU helper reports it.
        let count = parse_u32(count).ok_or_else(|| usage(tool))?;
        if count == 0 {
            return Err(MapError::NotAllowed(format!(
                "sub{} overflow detected.",
                tool.id()
            )));
        }
        let m = Mapping {
            inside,
            outside,
            count,
        };
        if m.inside_end() > u64::from(u32::MAX) + 1 || m.outside_end() > u64::from(u32::MAX) + 1 {
            return Err(MapError::NotAllowed(format!(
                "sub{} overflow detected.",
                tool.id()
            )));
        }
        mappings.push(m);
    }
    if mappings.len() > MAX_LINES {
        return Err(MapError::NotAllowed(format!(
            "too many ranges: the kernel accepts at most {MAX_LINES}"
        )));
    }
    Ok((target, mappings))
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

/// Who is asking.
#[derive(Debug, Clone)]
struct Caller {
    name: String,
    /// Real uid and gid: what the kernel will hold the caller to.
    uid: u32,
    gid: u32,
    /// The account's own ids, from the password database.
    pw_uid: u32,
    pw_gid: u32,
}

/// The ranges granted to the caller in `/etc/subuid` or `/etc/subgid`.
///
/// An entry names its owner either by login name or by numeric uid; both
/// spellings grant. Note that for `newgidmap` too the owner is the *user*: the
/// files list which user may map which subordinate ids.
fn granted_ranges(entries: &[SubIdEntry], caller: &Caller) -> Vec<(u64, u64)> {
    let uid_text = caller.uid.to_string();
    entries
        .iter()
        .filter(|e| e.name == caller.name || e.name == uid_text)
        .map(|e| (e.start, e.start + e.count))
        .collect()
}

/// Check every requested range against what the caller may map.
///
/// A range is allowed when it lies inside one granted range, or when it is the
/// caller's own id mapped once: the kernel lets an unprivileged process map
/// its own id into a namespace it created, so refusing it here would take
/// away something the caller already had. Root is not exempt from the
/// `/etc/subuid` requirement, as newuidmap(1) says in so many words.
fn check_allowed(
    tool: Tool,
    mappings: &[Mapping],
    granted: &[(u64, u64)],
    own_id: u32,
) -> Result<(), MapError> {
    for m in mappings {
        let start = u64::from(m.outside);
        let end = m.outside_end();
        let own = m.count == 1 && m.outside == own_id;
        let inside_grant = granted.iter().any(|(gs, ge)| *gs <= start && end <= *ge);
        if !(own || inside_grant) {
            return Err(MapError::NotAllowed(format!(
                "{id} range [{}-{}) -> [{}-{}) not allowed",
                m.inside,
                m.inside_end(),
                m.outside,
                m.outside_end(),
                id = tool.id()
            )));
        }
    }
    Ok(())
}

/// Refuse ranges that overlap, on either side.
///
/// The kernel refuses them too, with `EINVAL` and nothing else; naming the
/// problem costs nothing and cannot change any outcome the kernel would have
/// accepted.
fn check_no_overlap(tool: Tool, mappings: &[Mapping]) -> Result<(), MapError> {
    for (i, a) in mappings.iter().enumerate() {
        for b in &mappings[i + 1..] {
            let inside_clash =
                u64::from(a.inside) < b.inside_end() && u64::from(b.inside) < a.inside_end();
            let outside_clash =
                u64::from(a.outside) < b.outside_end() && u64::from(b.outside) < a.outside_end();
            if inside_clash || outside_clash {
                return Err(MapError::NotAllowed(format!(
                    "{id} ranges [{}-{}) -> [{}-{}) and [{}-{}) -> [{}-{}) overlap",
                    a.inside,
                    a.inside_end(),
                    a.outside,
                    a.outside_end(),
                    b.inside,
                    b.inside_end(),
                    b.outside,
                    b.outside_end(),
                    id = tool.id()
                )));
            }
        }
    }
    Ok(())
}

/// The bytes the kernel wants: one `inside outside count` line per range,
/// delivered in a single write.
fn render(mappings: &[Mapping]) -> String {
    let mut out = String::new();
    for m in mappings {
        let _ = writeln!(out, "{} {} {}", m.inside, m.outside, m.count);
    }
    out
}

// ---------------------------------------------------------------------------
// The target process
// ---------------------------------------------------------------------------

/// Open `/proc/<pid>` (or adopt the caller's descriptor) and check that the
/// process belongs to the caller.
///
/// Everything afterwards goes through this descriptor -- `openat` for the map
/// file -- so a pid recycled between the check and the write cannot redirect
/// it: the descriptor stays bound to the process it was opened on.
fn open_target(target: Target, caller: &Caller) -> Result<OwnedFd, MapError> {
    use rustix::fs::{Mode, OFlags};

    let dir = match target {
        Target::Pid(pid) => rustix::fs::open(
            format!("/proc/{pid}"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| {
            MapError::Target(format!(
                "Could not open proc directory for target {pid}: {e}"
            ))
        })?,
        // The caller's descriptor is re-opened through its /proc/self/fd
        // entry, a magic link that resolves to the object the descriptor
        // refers to rather than to a path -- so this is the same /proc/<pid>
        // instance the caller checked, and no raw descriptor is adopted.
        Target::Fd(fd) => rustix::fs::open(
            format!("/proc/self/fd/{fd}"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| {
            MapError::Usage(format!(
                "fd:{fd} is not a descriptor open on a /proc/<pid> directory: {e}"
            ))
        })?,
    };

    let st = rustix::fs::fstat(&dir)
        .map_err(|e| MapError::Target(format!("cannot stat the target: {e}")))?;
    if !rustix::fs::FileType::from_raw_mode(st.st_mode).is_dir() {
        return Err(MapError::Usage(
            "the fd: argument must be a descriptor open on a /proc/<pid> directory".into(),
        ));
    }
    // GNU's exact wording, which names all three ids on each side so an
    // administrator can see which of them disagrees.
    if st.st_uid != caller.uid
        || st.st_uid != caller.pw_uid
        || st.st_gid != caller.gid
        || st.st_gid != caller.pw_gid
    {
        return Err(MapError::Target(format!(
            "Target process is owned by a different user: uid:{} pw_uid:{} st_uid:{}, gid:{} pw_gid:{} st_gid:{}",
            caller.uid, caller.pw_uid, st.st_uid, caller.gid, caller.pw_gid, st.st_gid
        )));
    }
    Ok(dir)
}

/// Write the map through the target's directory descriptor, in one write.
fn write_map(tool: Tool, dir: &OwnedFd, contents: &str) -> Result<(), MapError> {
    use rustix::fs::{Mode, OFlags};

    let file = rustix::fs::openat(
        dir.as_fd(),
        tool.map_file(),
        OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|e| MapError::Write(format!("cannot open {}: {e}", tool.map_file())))?;
    // A single write at offset zero is the only form the kernel takes: a
    // partial write, or a second one, is refused wholesale.
    match rustix::io::write(&file, contents.as_bytes()) {
        Ok(n) if n == contents.len() => Ok(()),
        Ok(n) => Err(MapError::Write(format!(
            "write to {} was short: {n} of {} bytes",
            tool.map_file(),
            contents.len()
        ))),
        Err(e) => Err(MapError::Write(format!(
            "write to {} failed: {e}",
            tool.map_file()
        ))),
    }
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Entry point for the `newuidmap` utility.
#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    run(Tool::Uid, args)
}

/// Build the clap `Command` for `newuidmap`.
#[must_use]
pub fn uu_app() -> Command {
    app(Tool::Uid)
}

/// Run either helper.
pub fn run(tool: Tool, args: impl uucore::Args) -> UResult<()> {
    // A setuid helper with no children and no prompts: the full hardening,
    // including a sanitized environment, costs nothing here.
    shadow_core::hardening::harden_process();

    let Some(matches) = shadow_core::cli::parse_args(app(tool), args, |_| 1)? else {
        return Ok(());
    };
    let operands: Vec<String> = matches
        .get_many::<String>(options::ARGS)
        .map(|v| v.cloned().collect())
        .unwrap_or_default();

    let (target, mappings) = parse_args(tool, &operands)?;

    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    let entry = shadow_core::hardening::lookup_passwd_entry_by_uid(uid)
        .map_err(|e| MapError::Target(format!("cannot identify the caller: {e}")))?;
    let caller = Caller {
        name: entry.name,
        uid,
        gid,
        pw_uid: entry.uid,
        pw_gid: entry.gid,
    };

    // Checks first, in an order that reveals nothing about the target to a
    // caller who may not map anything: the ranges are judged before the
    // process is looked at.
    let root = shadow_core::sysroot::SysRoot::default();
    let entries = shadow_core::subid::read_subid_file(&tool.subid_path(&root)).unwrap_or_default();
    let granted = granted_ranges(&entries, &caller);
    let own_id = match tool {
        Tool::Uid => caller.uid,
        Tool::Gid => caller.gid,
    };
    check_no_overlap(tool, &mappings)?;
    check_allowed(tool, &mappings, &granted, own_id)?;

    let dir = open_target(target, &caller)?;
    write_map(tool, &dir, &render(&mappings))?;
    Ok(())
}

/// Build the clap `Command` for either helper.
#[must_use]
pub fn app(tool: Tool) -> Command {
    Command::new(tool.name())
        .about(match tool {
            Tool::Uid => "Set the user ID mapping of a user namespace",
            Tool::Gid => "Set the group ID mapping of a user namespace",
        })
        .override_usage(format!(
            "{} [<pid>|fd:<pidfd>] <{id}> <lower{id}> <count> [ <{id}> <lower{id}> <count> ] ...",
            tool.name(),
            id = tool.id()
        ))
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::ARGS)
                .help("the target process, then one or more inside/outside/count triples")
                .value_name("pid id lowerid count...")
                .num_args(0..)
                .index(1),
        )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn caller() -> Caller {
        Caller {
            name: "alice".to_string(),
            uid: 1000,
            gid: 1000,
            pw_uid: 1000,
            pw_gid: 1000,
        }
    }

    fn entry(name: &str, start: u64, count: u64) -> SubIdEntry {
        SubIdEntry {
            name: name.to_string(),
            start,
            count,
        }
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn test_apps_build() {
        app(Tool::Uid).debug_assert();
        app(Tool::Gid).debug_assert();
    }

    #[test]
    fn test_parse_pid_and_triples() {
        let (t, m) = parse_args(
            Tool::Uid,
            &args(&["1234", "0", "100000", "65536", "65536", "1000", "1"]),
        )
        .expect("parses");
        assert_eq!(t, Target::Pid(1234));
        assert_eq!(m.len(), 2);
        assert_eq!(
            m[0],
            Mapping {
                inside: 0,
                outside: 100_000,
                count: 65_536
            }
        );
        assert_eq!(
            m[1],
            Mapping {
                inside: 65_536,
                outside: 1000,
                count: 1
            }
        );
    }

    #[test]
    fn test_parse_fd_form() {
        let (t, _) = parse_args(Tool::Uid, &args(&["fd:3", "0", "100000", "10"])).expect("parses");
        assert_eq!(t, Target::Fd(3));
        assert!(parse_args(Tool::Uid, &args(&["fd:", "0", "1", "1"])).is_err());
        assert!(parse_args(Tool::Uid, &args(&["fd:x", "0", "1", "1"])).is_err());
    }

    /// Operands that are not triples, and numbers that are not plain
    /// decimals, are usage errors; a count that is not positive is the
    /// overflow message, as the GNU helper words it.
    #[test]
    fn test_parse_rejections() {
        assert!(matches!(
            parse_args(Tool::Uid, &args(&[])),
            Err(MapError::Usage(_))
        ));
        assert!(matches!(
            parse_args(Tool::Uid, &args(&["1234"])),
            Err(MapError::Usage(_))
        ));
        assert!(matches!(
            parse_args(Tool::Uid, &args(&["1234", "0", "100000"])),
            Err(MapError::Usage(_))
        ));
        assert!(matches!(
            parse_args(Tool::Uid, &args(&["1234", "0", "100000", "many"])),
            Err(MapError::Usage(_))
        ));
        assert!(matches!(
            parse_args(Tool::Uid, &args(&["1234", "-1", "100000", "1"])),
            Err(MapError::Usage(_))
        ));
        assert!(matches!(
            parse_args(Tool::Uid, &args(&["abc", "0", "1", "1"])),
            Err(MapError::Usage(_))
        ));
        let zero =
            parse_args(Tool::Uid, &args(&["1234", "0", "100000", "0"])).expect_err("refused");
        assert_eq!(zero.to_string(), "subuid overflow detected.");
        let over =
            parse_args(Tool::Gid, &args(&["1234", "0", "4294967295", "2"])).expect_err("refused");
        assert_eq!(over.to_string(), "subgid overflow detected.");
    }

    /// Both spellings of the owner grant: the login name and the numeric uid.
    #[test]
    fn test_granted_ranges_by_name_and_by_uid() {
        let entries = vec![
            entry("alice", 100_000, 65_536),
            entry("1000", 200_000, 1000),
            entry("bob", 300_000, 1000),
        ];
        let g = granted_ranges(&entries, &caller());
        assert_eq!(g, vec![(100_000, 165_536), (200_000, 201_000)]);
    }

    /// A range is allowed inside a grant, refused when it pokes out, and the
    /// caller's own id maps once without any grant.
    #[test]
    fn test_check_allowed() {
        let granted = vec![(100_000u64, 165_536u64)];
        let ok = [Mapping {
            inside: 0,
            outside: 100_000,
            count: 65_536,
        }];
        assert!(check_allowed(Tool::Uid, &ok, &granted, 1000).is_ok());

        let partly = [Mapping {
            inside: 0,
            outside: 165_530,
            count: 10,
        }];
        let err = check_allowed(Tool::Uid, &partly, &granted, 1000).expect_err("refused");
        assert_eq!(
            err.to_string(),
            "uid range [0-10) -> [165530-165540) not allowed"
        );

        let own = [Mapping {
            inside: 0,
            outside: 1000,
            count: 1,
        }];
        assert!(check_allowed(Tool::Uid, &own, &[], 1000).is_ok());
        let own_twice = [Mapping {
            inside: 0,
            outside: 1000,
            count: 2,
        }];
        assert!(check_allowed(Tool::Uid, &own_twice, &[], 1000).is_err());
        let someone_else = [Mapping {
            inside: 0,
            outside: 1001,
            count: 1,
        }];
        assert!(check_allowed(Tool::Uid, &someone_else, &[], 1000).is_err());
    }

    /// Root is not exempt: with no grant, root may map only itself once.
    #[test]
    fn test_root_is_not_exempt() {
        let big = [Mapping {
            inside: 0,
            outside: 100_000,
            count: 10,
        }];
        assert!(check_allowed(Tool::Uid, &big, &[], 0).is_err());
        let self_only = [Mapping {
            inside: 0,
            outside: 0,
            count: 1,
        }];
        assert!(check_allowed(Tool::Uid, &self_only, &[], 0).is_ok());
    }

    #[test]
    fn test_overlap_is_refused_on_either_side() {
        let inside = [
            Mapping {
                inside: 0,
                outside: 100_000,
                count: 10,
            },
            Mapping {
                inside: 5,
                outside: 200_000,
                count: 10,
            },
        ];
        assert!(check_no_overlap(Tool::Uid, &inside).is_err());
        let outside = [
            Mapping {
                inside: 0,
                outside: 100_000,
                count: 10,
            },
            Mapping {
                inside: 10,
                outside: 100_005,
                count: 10,
            },
        ];
        assert!(check_no_overlap(Tool::Uid, &outside).is_err());
        let touching = [
            Mapping {
                inside: 0,
                outside: 100_000,
                count: 10,
            },
            Mapping {
                inside: 10,
                outside: 100_010,
                count: 10,
            },
        ];
        assert!(
            check_no_overlap(Tool::Uid, &touching).is_ok(),
            "adjacent is not overlapping"
        );
    }

    /// The bytes the kernel reads: one line per range, three numbers, one
    /// space, newline-terminated.
    #[test]
    fn test_render() {
        let m = [
            Mapping {
                inside: 0,
                outside: 1000,
                count: 1,
            },
            Mapping {
                inside: 1,
                outside: 100_000,
                count: 65_536,
            },
        ];
        assert_eq!(render(&m), "0 1000 1\n1 100000 65536\n");
    }

    #[test]
    fn test_every_failure_exits_one() {
        for e in [
            MapError::Usage("x".into()),
            MapError::Target("x".into()),
            MapError::NotAllowed("x".into()),
            MapError::Write("x".into()),
        ] {
            assert_eq!(e.code(), 1);
        }
    }
}
