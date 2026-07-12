use std::env;
use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};

use mochi_user_syscall as syscall;

const EVENT_KIND_KEY: u16 = 1;
const FLAG_PRESS: u16 = 1 << 0;
const EAGAIN: i32 = 11;
const EAGAIN_U64: u64 = 11;

const KEY_BACKSPACE: u16 = 2;
const KEY_TAB: u16 = 3;
const KEY_ENTER: u16 = 4;
const KEY_ESCAPE: u16 = 1;
const KEY_A: u16 = 32;
const KEY_N: u16 = 45;
const KEY_S: u16 = 50;
const KEY_U: u16 = 52;
const KEY_Y: u16 = 56;
const CAPABILITY_DECISION_OPCODE: u32 = 0x4350_5244;
const RESOLVE_CAPS_OPCODE: u32 = 0x4341_5053;
const CAPABILITY_SERVICE_NAME: &str = "capability.service";
const MAX_APP_METADATA_BYTES: usize = 64 * 1024;
const ROLE_APPLICATION: u64 = 3;

static SHELL_ENDPOINT: AtomicU64 = AtomicU64::new(0);

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CapabilityDecision {
    AllowOnce = 1,
    AllowForProcess = 2,
    AllowPersistently = 3,
    AllowAllUserGrantable = 4,
    Deny = 5,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapabilityDecisionRequest {
    opcode: u32,
    decision: CapabilityDecision,
    reserved: u64,
    request: CapabilityPromptRequest,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum CapabilityClass {
    #[default]
    UserGrantable = 1,
    Privileged = 2,
    SystemOnly = 3,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapabilityExecutableIdentity {
    path_len: u16,
    reserved: u16,
    digest: [u8; 32],
    path: [u8; 256],
}

impl Default for CapabilityExecutableIdentity {
    fn default() -> Self {
        Self {
            path_len: 0,
            reserved: 0,
            digest: [0; 32],
            path: [0; 256],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapabilityResourceDescriptor {
    kind: u32,
    path_len: u16,
    reserved: u16,
    path: [u8; 256],
}

impl Default for CapabilityResourceDescriptor {
    fn default() -> Self {
        Self {
            kind: 0,
            path_len: 0,
            reserved: 0,
            path: [0; 256],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapabilityPromptRequest {
    opcode: u32,
    process_id: u64,
    executable: CapabilityExecutableIdentity,
    capability_class: CapabilityClass,
    capability_len: u16,
    resource: CapabilityResourceDescriptor,
    reason_len: u16,
    interactive: u8,
    decision_scope: u8,
    reserved0: u16,
    capability: [u8; 64],
    reason: [u8; 128],
}

impl Default for CapabilityPromptRequest {
    fn default() -> Self {
        Self {
            opcode: 0,
            process_id: 0,
            executable: CapabilityExecutableIdentity::default(),
            capability_class: CapabilityClass::UserGrantable,
            capability_len: 0,
            resource: CapabilityResourceDescriptor::default(),
            reason_len: 0,
            interactive: 0,
            decision_scope: 0,
            reserved0: 0,
            capability: [0; 64],
            reason: [0; 128],
        }
    }
}

impl CapabilityPromptRequest {
    fn capability(&self) -> &str {
        let len = self.capability_len as usize;
        core::str::from_utf8(&self.capability[..len]).unwrap_or("")
    }

    fn executable_path(&self) -> &str {
        let len = self.executable.path_len as usize;
        core::str::from_utf8(&self.executable.path[..len]).unwrap_or("")
    }

    fn resource_path(&self) -> Option<&str> {
        if self.resource.path_len == 0 {
            return None;
        }
        let len = self.resource.path_len as usize;
        core::str::from_utf8(&self.resource.path[..len]).ok()
    }
}

const CAPABILITY_PROMPT_OPCODE: u32 = 0x4350_5251;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct InputEvent {
    kind: u16,
    flags: u16,
    keycode: u16,
    detail: u16,
    codepoint: u32,
    value_x: i32,
    value_y: i32,
    value_z: i32,
    modifiers: u32,
    reserved: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PromptDecision {
    AllowOnce,
    AllowForProcess,
    AllowPersistently,
    AllowAllUserGrantable,
    Deny,
}

#[derive(Clone, Copy)]
struct PendingPrompt {
    sender: u64,
    request: CapabilityPromptRequest,
}

#[derive(Clone, Debug, Default)]
struct ExecutionPromptPolicy {
    deny_prompts: bool,
    allow_all_user: bool,
    background: bool,
    allow_session: Vec<String>,
}

#[derive(Clone, Copy, Default)]
struct FontMetrics {
    width: usize,
    height: usize,
}

fn load_font_metrics(path: &str) -> io::Result<FontMetrics> {
    let text = fs::read_to_string(path)?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("FONTBOUNDINGBOX ") {
            let mut parts = rest.split_whitespace();
            let width = parts
                .next()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(8);
            let height = parts
                .next()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(8);
            return Ok(FontMetrics { width, height });
        }
    }
    Ok(FontMetrics {
        width: 8,
        height: 8,
    })
}

fn prompt_string() -> String {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    format!("{} $ ", cwd.display())
}

fn print_prompt() -> io::Result<()> {
    print!("{}", prompt_string());
    io::stdout().flush()
}

fn print_capability_prompt(request: &CapabilityPromptRequest) -> io::Result<()> {
    let executable = request.executable_path();
    let capability = request.capability();
    let resource = request.resource_path().unwrap_or("(none)");
    println!();
    println!("{executable} is requesting an additional permission.");
    println!();
    println!("Permission:");
    println!("  {capability}");
    println!();
    println!("Resource:");
    println!("  {resource}");
    println!();
    println!("[y] Allow once");
    println!("[s] Allow for this process");
    println!("[a] Always allow this permission");
    println!("[u] Allow all user-grantable permissions without asking again");
    println!("[n] Deny");
    io::stdout().flush()
}

fn decision_from_key(ch: char) -> Option<PromptDecision> {
    match ch {
        'y' | 'Y' => Some(PromptDecision::AllowOnce),
        's' | 'S' => Some(PromptDecision::AllowForProcess),
        'a' | 'A' => Some(PromptDecision::AllowPersistently),
        'u' | 'U' => Some(PromptDecision::AllowAllUserGrantable),
        'n' | 'N' => Some(PromptDecision::Deny),
        _ => None,
    }
}

fn prompt_decision_value(decision: PromptDecision) -> u32 {
    match decision {
        PromptDecision::AllowOnce => CapabilityDecision::AllowOnce as u32,
        PromptDecision::AllowForProcess => CapabilityDecision::AllowForProcess as u32,
        PromptDecision::AllowPersistently => CapabilityDecision::AllowPersistently as u32,
        PromptDecision::AllowAllUserGrantable => CapabilityDecision::AllowAllUserGrantable as u32,
        PromptDecision::Deny => CapabilityDecision::Deny as u32,
    }
}

fn capability_decision(decision: PromptDecision) -> CapabilityDecision {
    match decision {
        PromptDecision::AllowOnce => CapabilityDecision::AllowOnce,
        PromptDecision::AllowForProcess => CapabilityDecision::AllowForProcess,
        PromptDecision::AllowPersistently => CapabilityDecision::AllowPersistently,
        PromptDecision::AllowAllUserGrantable => CapabilityDecision::AllowAllUserGrantable,
        PromptDecision::Deny => CapabilityDecision::Deny,
    }
}

fn redraw_line(line: &str) -> io::Result<()> {
    print!("\n{}{}", prompt_string(), line);
    io::stdout().flush()
}

fn resolve_command_path(cmd: &str) -> io::Result<String> {
    let path = if cmd.contains('/') {
        let path = PathBuf::from(cmd);
        if cmd.ends_with(".app") {
            resolve_app_entry(&path)?
        } else {
            path
        }
    } else if cmd.ends_with(".app") {
        resolve_app_entry(&PathBuf::from("/applications").join(cmd))?
    } else {
        return Ok(format!("/bin/{cmd}"));
    };

    Ok(path.to_string_lossy().into_owned())
}

fn resolve_app_entry(app_root: &Path) -> io::Result<PathBuf> {
    let about_path = app_root.join("about.toml");
    let manifest_path = app_root.join("manifest.toml");
    let about = read_text_file_bounded(&about_path, MAX_APP_METADATA_BYTES).map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{}: app about.toml not found", app_root.display()),
        )
    })?;
    let manifest =
        read_text_file_bounded(&manifest_path, MAX_APP_METADATA_BYTES).map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{}: app manifest.toml not found", app_root.display()),
            )
        })?;

    let entry = parse_toml_string_field(&about, "entry")
        .or_else(|| parse_toml_string_field(&manifest, "path"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: app entry not found", app_root.display()),
            )
        })?;

    let entry_path = PathBuf::from(entry);
    if entry_path.is_absolute() {
        Ok(entry_path)
    } else {
        Ok(app_root.join(entry_path))
    }
}

fn read_text_file_bounded(path: &Path, max_bytes: usize) -> io::Result<String> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: app metadata too large", path.display()),
        ));
    }
    String::from_utf8(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: invalid utf-8", path.display()),
        )
    })
}

fn parse_toml_string_field(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        let Some((field, value)) = line.trim().split_once('=') else {
            continue;
        };
        if field.trim() != key {
            continue;
        }
        return parse_toml_string_literal(value);
    }
    None
}

fn parse_toml_string_literal(value: &str) -> Option<String> {
    let value = value.trim();
    if !value.starts_with('"') {
        return None;
    }
    let mut output = String::new();
    let mut chars = value[1..].chars();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => return Some(output),
            '\\' => match chars.next()? {
                '"' => output.push('"'),
                '\\' => output.push('\\'),
                'n' => output.push('\n'),
                'r' => output.push('\r'),
                't' => output.push('\t'),
                other => output.push(other),
            },
            other => output.push(other),
        }
    }
    None
}

fn change_dir(target: &str) -> io::Result<()> {
    let c_target = CString::new(target)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let rc = unsafe { libc::chdir(c_target.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn parse_external_options(argv: &[String]) -> io::Result<(ExecutionPromptPolicy, &[String])> {
    let mut policy = ExecutionPromptPolicy::default();
    let mut index = 0;
    while index < argv.len() {
        match argv[index].as_str() {
            "--deny-prompts" => {
                policy.deny_prompts = true;
                index += 1;
            }
            "--allow-all-user" => {
                policy.allow_all_user = true;
                index += 1;
            }
            "--background" => {
                policy.background = true;
                index += 1;
            }
            "--allow-session" => {
                let Some(capability) = argv.get(index + 1) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--allow-session requires capability",
                    ));
                };
                policy.allow_session.push(capability.clone());
                index += 2;
            }
            "--" => {
                index += 1;
                break;
            }
            _ => break,
        }
    }
    Ok((policy, &argv[index..]))
}

fn prompt_policy_decision(
    policy: &ExecutionPromptPolicy,
    request: &CapabilityPromptRequest,
) -> Option<PromptDecision> {
    if policy.deny_prompts {
        return Some(PromptDecision::Deny);
    }
    if policy.allow_all_user && request.capability_class == CapabilityClass::UserGrantable {
        return Some(PromptDecision::AllowAllUserGrantable);
    }
    let capability = request.capability();
    if policy
        .allow_session
        .iter()
        .any(|allowed| allowed.as_str() == capability)
    {
        return Some(PromptDecision::AllowForProcess);
    }
    None
}

fn spawn_external(argv: &[String], policy: &ExecutionPromptPolicy) -> io::Result<()> {
    if argv.is_empty() {
        return Ok(());
    }
    if policy.background && policy.allow_session.is_empty() && !policy.allow_all_user {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "--background requires --allow-session or --allow-all-user",
        ));
    }

    let is_app_bundle = argv[0].ends_with(".app");
    let path = resolve_command_path(&argv[0])?;
    let shell_endpoint = SHELL_ENDPOINT.load(Ordering::Relaxed);
    let shell_target_str = current_thread_id()?.to_string();
    let prompt_mode = if policy.deny_prompts {
        "deny"
    } else {
        "interactive"
    };

    if policy.background {
        eprintln!("msh: background launch path for {}", argv[0]);
        spawn_external_direct(&path, &argv[1..], &shell_target_str, prompt_mode)?;
        return wait_background_capability_request(shell_endpoint, policy);
    }

    if is_app_bundle {
        let pid = spawn_app_bundle_manifest(&path, &argv[1..], &shell_target_str, prompt_mode)?;
        return wait_foreground_pid(pid, policy);
    }

    let mut child = Command::new(&path)
        .args(&argv[1..])
        .env("MOCHI_EXECUTABLE_PATH", &path)
        .env("MOCHI_SHELL_ENDPOINT", shell_target_str)
        .env("MOCHI_PROMPT_MODE", prompt_mode)
        .spawn()?;
    wait_foreground_child(&mut child, policy)
}

fn encode_nul_list(items: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(item.as_bytes());
        out.push(0);
    }
    out
}

fn resolve_capabilities(entry_path: &str) -> io::Result<Vec<u8>> {
    let endpoint = syscall::call2(
        syscall::SyscallNumber::FindProcessByName,
        CAPABILITY_SERVICE_NAME.as_ptr() as u64,
        CAPABILITY_SERVICE_NAME.len() as u64,
    )
    .map_err(sys_error_to_io)?;
    if endpoint == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "capability.service not found",
        ));
    }

    let mut request = Vec::with_capacity(4 + entry_path.len());
    request.extend_from_slice(&RESOLVE_CAPS_OPCODE.to_le_bytes());
    request.extend_from_slice(entry_path.as_bytes());

    let mut reply = [0u8; 1024];
    let msg = syscall::call5(
        syscall::SyscallNumber::IpcCall,
        endpoint,
        request.as_ptr() as u64,
        request.len() as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
    )
    .map_err(sys_error_to_io)?;
    let len = (msg & 0xffff_ffff) as usize;
    if len < 8 || len > reply.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid capability.service reply",
        ));
    }
    let status = u64::from_le_bytes(
        reply[..8]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid status"))?,
    );
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }

    Ok(reply[8..len].to_vec())
}

fn spawn_app_bundle_manifest(
    path: &str,
    args: &[String],
    shell_endpoint: &str,
    prompt_mode: &str,
) -> io::Result<i32> {
    let c_path = CString::new(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid executable path"))?;
    let mut exec_args = Vec::with_capacity(args.len() + 3);
    exec_args.push(format!("MOCHI_EXECUTABLE_PATH={path}"));
    exec_args.push(format!("MOCHI_SHELL_ENDPOINT={shell_endpoint}"));
    exec_args.push(format!("MOCHI_PROMPT_MODE={prompt_mode}"));
    exec_args.extend(args.iter().cloned());
    let args_nul = encode_nul_list(&exec_args);
    let caps_nul = resolve_capabilities(path)?;

    eprintln!("msh: fork exec {}", path);
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let error = io::Error::last_os_error();
        eprintln!("msh: fork failed: {error}");
        return Err(error);
    }
    if pid == 0 {
        unsafe {
            let result = syscall::raw_syscall5(
                syscall::SyscallNumber::ExecManifest,
                c_path.as_ptr() as u64,
                args_nul.as_ptr() as u64,
                caps_nul.as_ptr() as u64,
                caps_nul.len() as u64,
                ROLE_APPLICATION,
            );
            write_execve_failed_result(result.raw() as i64);
            libc::_exit(127);
        }
    }
    eprintln!("msh: forked child pid={pid}");
    Ok(pid)
}

fn spawn_external_direct(
    path: &str,
    args: &[String],
    shell_endpoint: &str,
    prompt_mode: &str,
) -> io::Result<i32> {
    let c_path = CString::new(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid executable path"))?;
    let mut c_args = Vec::with_capacity(args.len() + 1);
    c_args.push(c_path.clone());
    for arg in args {
        c_args.push(
            CString::new(arg.as_str())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid argument"))?,
        );
    }
    let env_exe = CString::new(format!("MOCHI_EXECUTABLE_PATH={path}"))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid executable path"))?;
    let env_shell = CString::new(format!("MOCHI_SHELL_ENDPOINT={shell_endpoint}"))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid shell endpoint"))?;
    let env_prompt = CString::new(format!("MOCHI_PROMPT_MODE={prompt_mode}"))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid prompt mode"))?;

    eprintln!("msh: fork exec {}", path);
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let error = io::Error::last_os_error();
        eprintln!("msh: fork failed: {error}");
        return Err(error);
    }
    if pid == 0 {
        let mut argv: Vec<*const i8> = c_args.iter().map(|arg| arg.as_ptr()).collect();
        argv.push(core::ptr::null());
        let exec_path_ptr = argv[0];
        let envp = [
            env_exe.as_ptr(),
            env_shell.as_ptr(),
            env_prompt.as_ptr(),
            core::ptr::null(),
        ];
        let argv_ptr = argv.as_ptr();
        let envp_ptr = envp.as_ptr();
        unsafe {
            let result = syscall::raw_syscall3(
                syscall::SyscallNumber::Execve,
                exec_path_ptr as u64,
                argv_ptr as u64,
                envp_ptr as u64,
            );
            write_execve_failed_result(result.raw() as i64);
            libc::_exit(127);
        }
    }
    eprintln!("msh: forked child pid={pid}");
    Ok(pid)
}

unsafe fn write_execve_failed_result(result: i64) {
    let errno = if result < 0 {
        result.saturating_neg() as u32
    } else {
        result as u32
    };
    let mut buf = [0u8; 48];
    let prefix = b"msh: execve failed errno=";
    let mut len = prefix.len();
    buf[..prefix.len()].copy_from_slice(prefix);

    if errno == 0 {
        buf[len] = b'0';
        len += 1;
    } else {
        let mut value = errno;
        let mut digits = [0u8; 10];
        let mut digit_len = 0usize;
        while value != 0 && digit_len < digits.len() {
            digits[digit_len] = b'0' + (value % 10) as u8;
            value /= 10;
            digit_len += 1;
        }
        while digit_len != 0 {
            digit_len -= 1;
            buf[len] = digits[digit_len];
            len += 1;
        }
    }
    buf[len] = b'\n';
    len += 1;
    let _ = unsafe { libc::write(2, buf.as_ptr().cast(), len) };
}

fn run_command(line: &str) -> io::Result<bool> {
    let argv: Vec<String> = line.split_whitespace().map(ToOwned::to_owned).collect();
    if argv.is_empty() {
        return Ok(true);
    }

    match argv[0].as_str() {
        "exit" => Ok(false),
        "echo" => {
            println!("{}", argv[1..].join(" "));
            Ok(true)
        }
        "pwd" => {
            println!("{}", env::current_dir()?.display());
            Ok(true)
        }
        "cd" => {
            let target = argv.get(1).map(String::as_str).unwrap_or("/");
            let path = std::path::Path::new(target);

            change_dir(target)?;
            Ok(true)
        }
        _ => {
            let (policy, external_argv) = parse_external_options(&argv)?;
            if external_argv.is_empty() {
                println!(
                    "usage: [--deny-prompts] [--allow-session capability] [--allow-all-user] [--background] command [args...]"
                );
                return Ok(true);
            }
            let path = match resolve_command_path(&external_argv[0]) {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("{}: {error}", external_argv[0]);
                    return Ok(true);
                }
            };
            if !path.ends_with(".app") && fs::metadata(&path).is_err() {
                println!("notfound");
                return Ok(true);
            }
            if let Err(error) = spawn_external(external_argv, &policy) {
                eprintln!("{}: {error}", external_argv[0]);
            }
            Ok(true)
        }
    }
}

fn handle_key_event(line: &mut String, event: InputEvent) -> io::Result<Option<String>> {
    if event.kind != EVENT_KIND_KEY || (event.flags & FLAG_PRESS) == 0 {
        return Ok(None);
    }

    if event.codepoint != 0 {
        if let Some(ch) = char::from_u32(event.codepoint) {
            line.push(ch);
            print!("{ch}");
            io::stdout().flush()?;
        }
        return Ok(None);
    }

    match event.keycode {
        KEY_BACKSPACE => {
            if line.pop().is_some() {
                redraw_line(line)?;
            }
            Ok(None)
        }
        KEY_ENTER => {
            println!();
            let completed = line.clone();
            line.clear();
            Ok(Some(completed))
        }
        KEY_TAB => {
            for _ in 0..4 {
                line.push(' ');
            }
            print!("    ");
            io::stdout().flush()?;
            Ok(None)
        }
        _ => Ok(None),
    }
}

fn handle_prompt_key_event(
    prompt: &PendingPrompt,
    event: InputEvent,
) -> io::Result<Option<PromptDecision>> {
    if event.kind != EVENT_KIND_KEY || (event.flags & FLAG_PRESS) == 0 {
        return Ok(None);
    }

    if let Some(ch) = char::from_u32(event.codepoint) {
        if let Some(decision) = decision_from_key(ch) {
            return Ok(Some(decision));
        }
    }

    match event.keycode {
        KEY_Y => Ok(Some(PromptDecision::AllowOnce)),
        KEY_S => Ok(Some(PromptDecision::AllowForProcess)),
        KEY_A => Ok(Some(PromptDecision::AllowPersistently)),
        KEY_U => Ok(Some(PromptDecision::AllowAllUserGrantable)),
        KEY_N => Ok(Some(PromptDecision::Deny)),
        KEY_ENTER | KEY_ESCAPE => Ok(Some(PromptDecision::Deny)),
        _ => {
            let _ = prompt;
            Ok(None)
        }
    }
}

fn reply_prompt(prompt: &PendingPrompt, decision: PromptDecision) {
    let decision = authorize_prompt_decision(prompt, decision).unwrap_or(PromptDecision::Deny);
    let mut reply = [0u8; 8];
    reply[..4].copy_from_slice(&prompt_decision_value(decision).to_le_bytes());
    let _ = syscall::call3(
        syscall::SyscallNumber::IpcReply,
        prompt.sender,
        reply.as_ptr() as u64,
        reply.len() as u64,
    );
}

fn authorize_prompt_decision(
    prompt: &PendingPrompt,
    decision: PromptDecision,
) -> io::Result<PromptDecision> {
    if matches!(decision, PromptDecision::Deny) {
        return Ok(PromptDecision::Deny);
    }

    let endpoint = syscall::call2(
        syscall::SyscallNumber::FindProcessByName,
        CAPABILITY_SERVICE_NAME.as_ptr() as u64,
        CAPABILITY_SERVICE_NAME.len() as u64,
    )
    .map_err(sys_error_to_io)?;
    let request = CapabilityDecisionRequest {
        opcode: CAPABILITY_DECISION_OPCODE,
        decision: capability_decision(decision),
        reserved: prompt.request.process_id,
        request: prompt.request,
    };
    let mut reply = [0u8; 8];
    let msg = syscall::call5(
        syscall::SyscallNumber::IpcCall,
        endpoint,
        (&request as *const CapabilityDecisionRequest) as u64,
        core::mem::size_of::<CapabilityDecisionRequest>() as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
    )
    .map_err(sys_error_to_io)?;
    let len = (msg & 0xffff_ffff) as usize;
    if len < 8 {
        return Ok(PromptDecision::Deny);
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&reply[..8]);
    if u64::from_le_bytes(raw) == 0 {
        Ok(decision)
    } else {
        Ok(PromptDecision::Deny)
    }
}

fn sys_error_to_io(err: syscall::SysError) -> io::Error {
    io::Error::from_raw_os_error(err.errno().unwrap_or(syscall::EIO) as i32)
}

fn ipc_create() -> io::Result<u64> {
    syscall::call2(syscall::SyscallNumber::IpcCreate, 0, 0).map_err(sys_error_to_io)
}

fn current_thread_id() -> io::Result<u64> {
    syscall::call0(syscall::SyscallNumber::GetTid).map_err(sys_error_to_io)
}

fn ipc_send(endpoint: u64, bytes: &[u8]) -> io::Result<()> {
    syscall::call3(
        syscall::SyscallNumber::IpcSend,
        endpoint,
        bytes.as_ptr() as u64,
        bytes.len() as u64,
    )
    .map(|_| ())
    .map_err(sys_error_to_io)
}

fn ipc_wait(endpoint: u64, buf: &mut [u8]) -> io::Result<u64> {
    syscall::call3(
        syscall::SyscallNumber::IpcWait,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        endpoint,
    )
    .map_err(sys_error_to_io)
}

fn ipc_try_wait(buf: &mut [u8]) -> io::Result<Option<u64>> {
    match syscall::call3(
        syscall::SyscallNumber::IpcWait,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        0,
    ) {
        Ok(msg) => Ok(Some(msg)),
        Err(err) if err.errno() == Some(EAGAIN_U64) => Ok(None),
        Err(err) => Err(sys_error_to_io(err)),
    }
}

fn wait_foreground_child(child: &mut Child, policy: &ExecutionPromptPolicy) -> io::Result<()> {
    let mut buf = [0u8; core::mem::size_of::<CapabilityPromptRequest>()];
    let mut prompt: Option<PendingPrompt> = None;

    loop {
        if let Some(msg) = ipc_try_wait(&mut buf)? {
            let len = (msg & 0xffff_ffff) as usize;
            if let Some(current) = prompt.as_ref().copied() {
                if len == core::mem::size_of::<InputEvent>() {
                    let event =
                        unsafe { core::ptr::read_unaligned(buf.as_ptr().cast::<InputEvent>()) };
                    if let Some(decision) = handle_prompt_key_event(&current, event)? {
                        prompt = None;
                        reply_prompt(&current, decision);
                    }
                    continue;
                }
            }

            if let Some(request) = parse_capability_request(&buf[..len.min(buf.len())]) {
                let current = PendingPrompt {
                    sender: msg >> 32,
                    request,
                };
                if let Some(decision) = prompt_policy_decision(policy, &current.request) {
                    reply_prompt(&current, decision);
                    if policy.background {
                        return Ok(());
                    }
                } else {
                    print_capability_prompt(&current.request)?;
                    prompt = Some(current);
                }
            }
        }

        match child.try_wait() {
            Ok(Some(_status)) => {
                if prompt.is_some() {
                    println!();
                }
                return Ok(());
            }
            Ok(None) => {
                let _ = syscall::call0(syscall::SyscallNumber::ThreadYield);
            }
            Err(error)
                if policy.background
                    || error.raw_os_error() == Some(EAGAIN)
                    || error.kind() == io::ErrorKind::WouldBlock =>
            {
                let _ = syscall::call0(syscall::SyscallNumber::ThreadYield);
            }
            Err(error) => return Err(error),
        }
    }
}

fn wait_foreground_pid(pid: i32, policy: &ExecutionPromptPolicy) -> io::Result<()> {
    let mut buf = [0u8; core::mem::size_of::<CapabilityPromptRequest>()];
    let mut prompt: Option<PendingPrompt> = None;

    loop {
        if let Some(msg) = ipc_try_wait(&mut buf)? {
            let len = (msg & 0xffff_ffff) as usize;
            if let Some(current) = prompt.as_ref().copied() {
                if len == core::mem::size_of::<InputEvent>() {
                    let event =
                        unsafe { core::ptr::read_unaligned(buf.as_ptr().cast::<InputEvent>()) };
                    if let Some(decision) = handle_prompt_key_event(&current, event)? {
                        prompt = None;
                        reply_prompt(&current, decision);
                    }
                    continue;
                }
            }

            if let Some(request) = parse_capability_request(&buf[..len.min(buf.len())]) {
                let current = PendingPrompt {
                    sender: msg >> 32,
                    request,
                };
                if let Some(decision) = prompt_policy_decision(policy, &current.request) {
                    reply_prompt(&current, decision);
                    if policy.background {
                        return Ok(());
                    }
                } else {
                    print_capability_prompt(&current.request)?;
                    prompt = Some(current);
                }
            }
        }

        let mut status = 0;
        let wait_result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if wait_result == pid {
            if prompt.is_some() {
                println!();
            }
            return Ok(());
        }
        if wait_result < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(EAGAIN) || error.kind() == io::ErrorKind::WouldBlock {
                let _ = syscall::call0(syscall::SyscallNumber::ThreadYield);
            } else {
                return Err(error);
            }
        } else {
            let _ = syscall::call0(syscall::SyscallNumber::ThreadYield);
        }
    }
}

fn wait_background_capability_request(
    endpoint: u64,
    policy: &ExecutionPromptPolicy,
) -> io::Result<()> {
    let mut buf = [0u8; core::mem::size_of::<CapabilityPromptRequest>()];
    for _ in 0..65_536 {
        let msg = match ipc_wait(endpoint, &mut buf) {
            Ok(msg) => msg,
            Err(error) if error.raw_os_error() == Some(EAGAIN) => {
                let _ = syscall::call0(syscall::SyscallNumber::ThreadYield);
                continue;
            }
            Err(error) => return Err(error),
        };
        let len = (msg & 0xffff_ffff) as usize;
        if let Some(request) = parse_capability_request(&buf[..len.min(buf.len())]) {
            let current = PendingPrompt {
                sender: msg >> 32,
                request,
            };
            if let Some(decision) = prompt_policy_decision(policy, &current.request) {
                reply_prompt(&current, decision);
                return Ok(());
            }
            print_capability_prompt(&current.request)?;
            return Ok(());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "background command did not request a session capability",
    ))
}

fn parse_endpoint_arg() -> io::Result<u64> {
    let mut args = env::args();
    let _program = args.next();
    let endpoint = args
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing endpoint arg"))?;
    endpoint
        .parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid endpoint arg"))
}

fn parse_capability_request(buf: &[u8]) -> Option<CapabilityPromptRequest> {
    if buf.len() < core::mem::size_of::<CapabilityPromptRequest>() {
        return None;
    }
    let req = unsafe { core::ptr::read_unaligned(buf.as_ptr().cast::<CapabilityPromptRequest>()) };
    if req.opcode != CAPABILITY_PROMPT_OPCODE {
        return None;
    }
    Some(req)
}

fn main() -> io::Result<()> {
    let _font = load_font_metrics("/system/resources/msh/ter-u12b.bdf")?;
    let tty_endpoint = parse_endpoint_arg()?;
    let endpoint = ipc_create()?;
    SHELL_ENDPOINT.store(endpoint, Ordering::Relaxed);
    let thread_id = current_thread_id()?;
    let mut shell_targets = [0u8; 16];
    shell_targets[..8].copy_from_slice(&endpoint.to_le_bytes());
    shell_targets[8..].copy_from_slice(&thread_id.to_le_bytes());
    ipc_send(tty_endpoint, &shell_targets)?;
    let mut line = String::new();
    let mut buf = [0u8; core::mem::size_of::<CapabilityPromptRequest>()];
    let mut prompt: Option<PendingPrompt> = None;

    print_prompt()?;
    loop {
        let msg = ipc_wait(endpoint, &mut buf)?;
        let len = (msg & 0xffff_ffff) as usize;
        if prompt.is_none() {
            if len == core::mem::size_of::<InputEvent>() {
                let event = unsafe { core::ptr::read_unaligned(buf.as_ptr().cast::<InputEvent>()) };
                if let Some(command) = handle_key_event(&mut line, event)? {
                    if !run_command(&command)? {
                        break;
                    }
                    print_prompt()?;
                }
                continue;
            }
            if let Some(request) = parse_capability_request(&buf[..len.min(buf.len())]) {
                let current = PendingPrompt {
                    sender: msg >> 32,
                    request,
                };
                print_capability_prompt(&current.request)?;
                prompt = Some(current);
                continue;
            }
            continue;
        }

        if let Some(current) = prompt.as_ref().copied() {
            if len == core::mem::size_of::<InputEvent>() {
                let event = unsafe { core::ptr::read_unaligned(buf.as_ptr().cast::<InputEvent>()) };
                if let Some(decision) = handle_prompt_key_event(&current, event)? {
                    prompt = None;
                    reply_prompt(&current, decision);
                    print_prompt()?;
                }
                continue;
            }
            if let Some(request) = parse_capability_request(&buf[..len.min(buf.len())]) {
                let sender = msg >> 32;
                let current = PendingPrompt { sender, request };
                print_capability_prompt(&current.request)?;
                prompt = Some(current);
            }
        }
    }
    Ok(())
}
