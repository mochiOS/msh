use std::env;
use std::ffi::CString;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use mochi_user_syscall as syscall;

const EVENT_KIND_KEY: u16 = 1;
const FLAG_PRESS: u16 = 1 << 0;

const KEY_BACKSPACE: u16 = 2;
const KEY_TAB: u16 = 3;
const KEY_ENTER: u16 = 4;

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
            let width = parts.next().and_then(|s| s.parse::<usize>().ok()).unwrap_or(8);
            let height = parts.next().and_then(|s| s.parse::<usize>().ok()).unwrap_or(8);
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

fn spawn_external(argv: &[String]) -> io::Result<()> {
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

    let envp: [*mut libc::c_char; 1] = [core::ptr::null_mut()];
    let mut pid: libc::pid_t = 0;
    let rc = unsafe {
        libc::posix_spawn(
            &mut pid,
            c_strings[0].as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            argv_ptrs.as_mut_ptr(),
            envp.as_ptr() as *mut *mut libc::c_char,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }

    let mut status = 0i32;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    if waited != pid {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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

            if path.exists() && !path.is_dir() {
                eprintln!("\"{target}\" isn't directory.");
                return Ok(true);
            }

            change_dir(target)?;
            Ok(true)
        }
        _ => {
            let path = resolve_command_path(&argv[0]);
            if fs::metadata(&path).is_err() {
                println!("notfound");
                return Ok(true);
            }
            spawn_external(&argv)?;
            Ok(true)
        }
    }
}

fn handle_key_event(line: &mut String, event: InputEvent) -> io::Result<Option<String>> {
    if event.kind != EVENT_KIND_KEY
        || (event.flags & FLAG_PRESS) == 0
    {
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

fn main() -> io::Result<()> {
    let _font = load_font_metrics("/system/resources/msh/ter-u12b.bdf")?;
    let endpoint = parse_endpoint_arg()?;
    let mut line = String::new();
    let mut buf = [0u8; core::mem::size_of::<InputEvent>()];

    print_prompt()?;
    loop {
        let msg = ipc_wait(endpoint, &mut buf)?;
        let len = (msg & 0xffff_ffff) as usize;
        if len < buf.len() {
            continue;
        }
        let event = unsafe { core::ptr::read_unaligned(buf.as_ptr().cast::<InputEvent>()) };
        if let Some(command) = handle_key_event(&mut line, event)? {
            if !run_command(&command)? {
                break;
            }
            print_prompt()?;
        }
    }
    Ok(())
}
