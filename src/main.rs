use std::env;
use std::ffi::CString;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use mochi_user_syscall as syscall;

const WNOHANG: libc::c_int = 1;
const EVENT_KIND_KEY: u16 = 1;
const FLAG_PRESS: u16 = 1 << 0;

const KEY_BACKSPACE: u16 = 2;
const KEY_TAB: u16 = 3;
const KEY_ENTER: u16 = 4;
const KEY_ESCAPE: u16 = 1;
const CAPABILITY_DECISION_OPCODE: u32 = 0x4350_5244;
const CAPABILITY_SERVICE_NAME: &str = "capability.service";

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
    println!("{} が追加の権限を要求しています。", executable);
    println!();
    println!("操作:");
    println!("  {}", capability);
    println!();
    println!("対象:");
    println!("  {}", resource);
    println!();
    println!("[y] 今回のみ許可");
    println!("[s] このプロセスの実行中は許可");
    println!("[a] 今後も許可");
    println!("[u] 今後は確認せず、ユーザー権限内で利用可能な権限をすべて許可");
    println!("[n] 拒否");
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

fn resolve_command_path(cmd: &str) -> String {
    if cmd.contains('/') {
        cmd.to_string()
    } else {
        format!("/bin/{cmd}")
    }
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

    let path = resolve_command_path(&argv[0]);
    let c_path = CString::new(path.clone())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "command contains NUL"))?;

    let mut c_strings = Vec::with_capacity(argv.len());
    c_strings.push(c_path);
    for arg in &argv[1..] {
        c_strings.push(
            CString::new(arg.as_str())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "arg contains NUL"))?,
        );
    }

    let mut argv_ptrs: Vec<*mut libc::c_char> = c_strings
        .iter()
        .map(|s| s.as_ptr() as *mut libc::c_char)
        .collect();
    argv_ptrs.push(core::ptr::null_mut());

    let shell_endpoint = SHELL_ENDPOINT.load(Ordering::Relaxed);
    let shell_endpoint_str = shell_endpoint.to_string();
    let exec_path_env = format!("MOCHI_EXECUTABLE_PATH={path}");
    let shell_endpoint_env = format!("MOCHI_SHELL_ENDPOINT={shell_endpoint_str}");
    let prompt_mode = if policy.deny_prompts {
        "deny"
    } else {
        "interactive"
    };
    let prompt_mode_env = format!("MOCHI_PROMPT_MODE={prompt_mode}");
    let env_strings = vec![
        CString::new(exec_path_env)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "env contains NUL"))?,
        CString::new(shell_endpoint_env)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "env contains NUL"))?,
        CString::new(prompt_mode_env)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "env contains NUL"))?,
    ];
    let mut envp: Vec<*mut libc::c_char> = env_strings
        .iter()
        .map(|s| s.as_ptr() as *mut libc::c_char)
        .collect();
    envp.push(core::ptr::null_mut());
    let mut pid: libc::pid_t = 0;
    let rc = unsafe {
        libc::posix_spawn(
            &mut pid,
            c_strings[0].as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            argv_ptrs.as_mut_ptr(),
            envp.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }

    wait_foreground_process(pid, policy)
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
                    "usage: [--deny-prompts] [--allow-session capability] [--allow-all-user] command [args...]"
                );
                return Ok(true);
            }
            let path = resolve_command_path(&external_argv[0]);
            if fs::metadata(&path).is_err() {
                println!("notfound");
                return Ok(true);
            }
            spawn_external(external_argv, &policy)?;
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
        reserved: prompt.sender,
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
        Err(err) if err.errno() == Some(syscall::EAGAIN) => Ok(None),
        Err(err) => Err(sys_error_to_io(err)),
    }
}

fn wait_foreground_process(pid: libc::pid_t, policy: &ExecutionPromptPolicy) -> io::Result<()> {
    let mut buf = [0u8; core::mem::size_of::<CapabilityPromptRequest>()];
    let mut prompt: Option<PendingPrompt> = None;

    loop {
        let mut status = 0i32;
        let waited = unsafe { libc::waitpid(pid, &mut status, WNOHANG) };
        if waited == pid {
            if prompt.is_some() {
                println!();
            }
            return Ok(());
        }
        if waited < 0 {
            return Err(io::Error::last_os_error());
        }

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
                } else {
                    print_capability_prompt(&current.request)?;
                    prompt = Some(current);
                }
            }
            continue;
        }

        let _ = syscall::call0(syscall::SyscallNumber::ThreadYield);
    }
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
    let endpoint = parse_endpoint_arg()?;
    SHELL_ENDPOINT.store(endpoint, Ordering::Relaxed);
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
