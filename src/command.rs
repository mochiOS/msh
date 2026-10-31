//! Build all external commands through the same POSIX spawn/search route.
//! A bare program remains bare so execvp/spawnp can use the captured PATH.
use std::process::Command;

pub(crate) fn create(
    program: &str,
    arguments: &[String],
    shell_endpoint: &str,
    prompt_mode: &str,
) -> Command {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env("MOCHI_EXECUTABLE_PATH", program)
        .env("MOCHI_SHELL_ENDPOINT", shell_endpoint)
        .env("MOCHI_PROMPT_MODE", prompt_mode);
    command
}
