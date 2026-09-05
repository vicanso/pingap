use vergen::{Build, Emitter};
use vergen_git2::Git2;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let build = Build::all_build();
    let git2 = Git2::all_git();

    Emitter::default()
        .add_instructions(&build)?
        .add_instructions(&git2)?
        .emit()?;

    Ok(())
}
