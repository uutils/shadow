// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Integration tests for every shadow-rs utility.
//!
//! One test binary, not fourteen. Each of the fourteen used to link all
//! fourteen tool crates and carry its own copy of the helpers through a
//! `#[path = "../common/mod.rs"]` include; this is the layout the rest of
//! uutils uses. The `#[path]` attributes are needed only because the
//! directory name carries a hyphen, which is not a module name.

mod common;

#[path = "by-util/test_chage.rs"]
mod test_chage;
#[path = "by-util/test_chfn.rs"]
mod test_chfn;
#[path = "by-util/test_chpasswd.rs"]
mod test_chpasswd;
#[path = "by-util/test_chsh.rs"]
mod test_chsh;
#[path = "by-util/test_fuzz_corpus.rs"]
mod test_fuzz_corpus;
#[path = "by-util/test_groupadd.rs"]
mod test_groupadd;
#[path = "by-util/test_groupdel.rs"]
mod test_groupdel;
#[path = "by-util/test_groupmod.rs"]
mod test_groupmod;
#[path = "by-util/test_grpck.rs"]
mod test_grpck;
#[path = "by-util/test_multicall.rs"]
mod test_multicall;
#[path = "by-util/test_newgrp.rs"]
mod test_newgrp;
#[path = "by-util/test_passwd.rs"]
mod test_passwd;
#[path = "by-util/test_pwck.rs"]
mod test_pwck;
#[path = "by-util/test_useradd.rs"]
mod test_useradd;
#[path = "by-util/test_userdel.rs"]
mod test_userdel;
#[path = "by-util/test_usermod.rs"]
mod test_usermod;
