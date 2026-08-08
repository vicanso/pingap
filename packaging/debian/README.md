# Debian maintainer scripts

cargo-deb generates the `postinst`/`prerm`/`postrm` for the systemd unit into
this directory at package time, driven by `[package.metadata.deb.systemd-units]`
in the root `Cargo.toml`. It only does so when `maintainer-scripts` points
somewhere, which is the only reason this directory exists: without it the unit
is installed but `systemctl daemon-reload` never runs and `purge` leaves the
unit registered.

Add a hand-written `postinst` etc. here if one is ever needed; cargo-deb merges
its generated fragments into an existing script rather than replacing it.
