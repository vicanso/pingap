use vergen::{Build, Emitter};
use vergen_git2::Git2;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let build = Build::all_build();
    let git2 = Git2::all_git();

    Emitter::default()
        // A source export or a crates.io tarball has no `.git`; vergen 10
        // then leaves VERGEN_GIT_* unset and `env!()` fails to compile.
        // Fall back to the idempotent placeholder instead; the binary shows
        // it as "unknown".
        .default_on_error()
        .add_instructions(&build)?
        .add_instructions(&git2)?
        .emit()?;

    Ok(())
}
