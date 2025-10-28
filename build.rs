use vergen::{BuildBuilder, Emitter};
use vergen_git2::Git2Builder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let build = BuildBuilder::all_build()?;
    let git2 = Git2Builder::all_git()?;

    Emitter::default()
        .add_instructions(&build)?
        .add_instructions(&git2)?
        .emit()?;

    Ok(())
}
