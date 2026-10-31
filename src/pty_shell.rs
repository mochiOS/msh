//! Interactive POSIX terminal ownership and shell-owned foreground jobs.
use super::{
    job_state::{Members, State},
    syntax,
};
use std::{
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::process::CommandExt,
    },
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static HANGUP: AtomicBool = AtomicBool::new(false);
extern "C" fn signal(number: i32) {
    if number == libc::SIGHUP {
        HANGUP.store(true, Ordering::Relaxed);
    } else {
        INTERRUPTED.store(true, Ordering::Relaxed);
    }
}
fn cvt(result: i32) -> io::Result<i32> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}
fn attributes(fd: i32) -> io::Result<libc::termios> {
    let mut value = std::mem::MaybeUninit::uninit();
    cvt(unsafe { libc::tcgetattr(fd, value.as_mut_ptr()) })?;
    Ok(unsafe { value.assume_init() })
}
fn duplicate(fd: i32) -> io::Result<OwnedFd> {
    let fd = cvt(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
struct Job {
    id: usize,
    group: i32,
    label: String,
    members: Members,
    attributes: Option<libc::termios>,
}
impl Job {
    fn notify(&self, number: i32) -> io::Result<()> {
        cvt(unsafe { libc::kill(-self.group, number) }).map(|_| ())
    }
    fn poll(&mut self) -> io::Result<State> {
        let entries: Vec<_> = self.members.entries().collect();
        for (pid, state) in entries {
            if state == State::Done {
                continue;
            }
            for _ in 0..32 {
                let mut status = 0;
                let result = unsafe {
                    libc::waitpid(
                        pid,
                        &mut status,
                        libc::WNOHANG | libc::WUNTRACED | libc::WCONTINUED,
                    )
                };
                if result == 0 {
                    break;
                }
                if result < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error);
                }
                let state = if libc::WIFSTOPPED(status) {
                    State::Stopped
                } else if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    State::Done
                } else {
                    State::Running
                };
                self.members.update(pid, state);
                if state == State::Done {
                    break;
                }
            }
        }
        Ok(self.members.state())
    }
    fn abort(&mut self) {
        let _ = self.notify(libc::SIGKILL);
        for (pid, state) in self.members.entries() {
            if state == State::Done {
                continue;
            }
            loop {
                let result = unsafe { libc::waitpid(pid, core::ptr::null_mut(), 0) };
                if result >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    break;
                }
            }
        }
    }
}
struct Restore<'a> {
    shell: &'a Shell,
    armed: bool,
}
impl Restore<'_> {
    fn restore(mut self) -> io::Result<()> {
        self.shell.restore()?;
        self.armed = false;
        Ok(())
    }
}
impl Drop for Restore<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.shell.restore();
        }
    }
}
struct Shell {
    tty: OwnedFd,
    group: i32,
    original: libc::termios,
    canonical: libc::termios,
    flags: i32,
    jobs: Vec<Job>,
    next_job: usize,
}
impl Shell {
    fn new(login: bool) -> io::Result<Self> {
        if login {
            cvt(unsafe { libc::login_tty(0) })?;
        }
        let tty = duplicate(0)?;
        let fd = tty.as_raw_fd();
        let group = unsafe { libc::getpgrp() };
        if cvt(unsafe { libc::tcgetpgrp(fd) })? != group {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "msh must start in the foreground",
            ));
        }
        let original = attributes(fd)?;
        let mut canonical = original;
        canonical.c_lflag |= libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN;
        canonical.c_iflag |= libc::ICRNL | libc::IUTF8;
        canonical.c_oflag |= libc::OPOST | libc::ONLCR;
        cvt(unsafe { libc::tcsetattr(fd, libc::TCSANOW, &canonical) })?;
        let flags = cvt(unsafe { libc::fcntl(fd, libc::F_GETFL) })? & !libc::O_NONBLOCK;
        cvt(unsafe { libc::fcntl(fd, libc::F_SETFL, flags) })?;
        // A shell must retain waitable child status even when its launcher
        // explicitly ignored SIGCHLD. Ignore would auto-reap our own jobs.
        if unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) } == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
        for number in [libc::SIGQUIT, libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU] {
            if unsafe { libc::signal(number, libc::SIG_IGN) } == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
        }
        for number in [libc::SIGINT, libc::SIGHUP] {
            if unsafe { libc::signal(number, signal as *const () as libc::sighandler_t) }
                == libc::SIG_ERR
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self {
            tty,
            group,
            original,
            canonical,
            flags,
            jobs: Vec::new(),
            next_job: 1,
        })
    }
    fn restore(&self) -> io::Result<()> {
        let fd = self.tty.as_raw_fd();
        cvt(unsafe { libc::tcsetpgrp(fd, self.group) })?;
        cvt(unsafe { libc::fcntl(fd, libc::F_SETFL, self.flags) })?;
        cvt(unsafe { libc::tcsetattr(fd, libc::TCSADRAIN, &self.canonical) })?;
        Ok(())
    }
    fn configure(&self, command: &mut Command, group: i32, foreground: bool) -> io::Result<()> {
        let tty = duplicate(self.tty.as_raw_fd())?;
        command.process_group(group);
        // Only async-signal-safe POSIX calls run between fork and exec. The
        // private CLOEXEC descriptor remains valid even after stdin redirects.
        unsafe {
            command.pre_exec(move || {
                if foreground {
                    cvt(libc::tcsetpgrp(tty.as_raw_fd(), libc::getpgrp()))?;
                }
                for number in [
                    libc::SIGINT,
                    libc::SIGQUIT,
                    libc::SIGTSTP,
                    libc::SIGTTIN,
                    libc::SIGTTOU,
                    libc::SIGHUP,
                ] {
                    if libc::signal(number, libc::SIG_DFL) == libc::SIG_ERR {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        Ok(())
    }
    fn refresh(&mut self) -> io::Result<()> {
        for job in &mut self.jobs {
            let before = job.members.state();
            let after = job.poll()?;
            if before != after {
                writeln!(io::stdout(), "[{}] {:?} {}", job.id, after, job.label)?;
            }
        }
        self.jobs.retain(|job| job.members.state() != State::Done);
        Ok(())
    }
    fn wait(&self, job: &mut Job) -> io::Result<()> {
        while job.poll()? == State::Running {
            // Ctrl+C may reach the shell during fork/exec, before the child
            // owns the terminal. Carry that interrupt into this exact job.
            if INTERRUPTED.swap(false, Ordering::Relaxed) {
                job.notify(libc::SIGINT)?;
            }
            super::drain_terminal_feedback()?;
            if HANGUP.load(Ordering::Relaxed) {
                let _ = job.notify(libc::SIGHUP);
                let _ = job.notify(libc::SIGCONT);
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "terminal hung up",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if job.members.state() == State::Stopped {
            job.attributes = Some(attributes(self.tty.as_raw_fd())?);
        }
        Ok(())
    }
    fn save(&mut self, mut job: Job) -> io::Result<()> {
        job.id = self.next_job;
        self.next_job = self
            .next_job
            .checked_add(1)
            .ok_or_else(|| io::Error::other("job number exhausted"))?;
        self.jobs.push(job);
        let job = self.jobs.last().unwrap();
        writeln!(
            io::stdout(),
            "[{}] {:?} {}",
            job.id,
            job.members.state(),
            job.label
        )?;
        Ok(())
    }
    fn launch(&mut self, pipeline: &syntax::Pipeline, label: &str) -> io::Result<()> {
        if self.jobs.len() >= 64 || self.next_job == usize::MAX {
            return Err(io::Error::other("too many jobs"));
        }
        let background =
            pipeline
                .commands
                .iter()
                .try_fold(pipeline.background, |background, spec| {
                    super::parse_external_options(&spec.argv)
                        .map(|(policy, _)| background || policy.background)
                })?;
        let restore = Restore {
            shell: self,
            armed: !background,
        };
        let mut job = Job {
            id: 0,
            group: 0,
            label: label.to_owned(),
            members: Members::new(),
            attributes: None,
        };
        let mut previous = None;
        let setup = (|| {
            for (index, spec) in pipeline.commands.iter().enumerate() {
                let (policy, argv) = super::parse_external_options(&spec.argv)?;
                let program = argv
                    .first()
                    .ok_or_else(|| io::Error::other("empty command"))?;
                if matches!(program.as_str(), "cd" | "exit" | "fg" | "bg" | "jobs")
                    || program.ends_with(".app")
                {
                    return Err(io::Error::other(
                        "this command cannot run as an external terminal job",
                    ));
                }
                let path = super::resolve_command_path(program)?;
                let endpoint = super::SHELL_ENDPOINT.load(Ordering::Relaxed).to_string();
                let mut command = super::command::create(
                    &path,
                    &argv[1..],
                    &endpoint,
                    if policy.deny_prompts {
                        "deny"
                    } else {
                        "interactive"
                    },
                );
                if let Some(stdout) = previous.take() {
                    command.stdin(Stdio::from(stdout));
                }
                if index + 1 != pipeline.commands.len() {
                    command.stdout(Stdio::piped());
                }
                super::apply_redirects(&mut command, &spec.redirects)?;
                self.configure(&mut command, job.group, !background)?;
                let mut child = command
                    .spawn()
                    .map_err(|error| io::Error::new(error.kind(), format!("{program}: {error}")))?;
                let pid = child.id() as i32;
                if job.group == 0 {
                    job.group = pid;
                }
                previous = child.stdout.take();
                job.members.push(pid);
            }
            Ok(())
        })();
        if let Err(error) = setup {
            drop(previous);
            if job.group != 0 {
                job.abort();
            }
            return Err(error);
        }
        if background {
            drop(restore);
            return self.save(job);
        }
        let waited = self.wait(&mut job);
        let restored = restore.restore();
        if job.members.state() != State::Done {
            self.save(job)?;
        }
        waited?;
        restored?;
        Ok(())
    }
    fn resume(&mut self, argument: Option<&String>, foreground: bool) -> io::Result<()> {
        let index = if let Some(argument) = argument {
            let id: usize = argument
                .trim_start_matches('%')
                .parse()
                .map_err(|_| io::Error::other("expected a job number"))?;
            self.jobs.iter().position(|job| job.id == id)
        } else {
            self.jobs.len().checked_sub(1)
        }
        .ok_or_else(|| io::Error::other("no such job"))?;
        let mut job = self.jobs.remove(index);
        if foreground {
            let restore = Restore {
                shell: self,
                armed: true,
            };
            let result = (|| {
                cvt(unsafe { libc::tcsetpgrp(self.tty.as_raw_fd(), job.group) })?;
                if let Some(attributes) = &job.attributes {
                    cvt(unsafe {
                        libc::tcsetattr(self.tty.as_raw_fd(), libc::TCSADRAIN, attributes)
                    })?;
                }
                job.notify(libc::SIGCONT)?;
                job.members.resume();
                self.wait(&mut job)
            })();
            let restored = restore.restore();
            if job.members.state() != State::Done {
                self.jobs.insert(index, job);
            }
            result?;
            restored?;
        } else {
            let result = job.notify(libc::SIGCONT);
            if result.is_ok() {
                job.members.resume();
            }
            self.jobs.insert(index, job);
            result?;
        }
        Ok(())
    }
    fn command(&mut self, line: &str) -> io::Result<bool> {
        let pipeline = syntax::parse_pipeline(line).map_err(io::Error::other)?;
        let Some(spec) = pipeline.commands.first() else {
            return Ok(true);
        };
        if pipeline.commands.len() == 1 && !pipeline.background {
            let argv = &spec.argv;
            match argv[0].as_str() {
                "jobs" => {
                    let mut output = super::builtin_output(&spec.redirects)?;
                    for job in &self.jobs {
                        writeln!(
                            output,
                            "[{}] {:?} {}",
                            job.id,
                            job.members.state(),
                            job.label
                        )?;
                    }
                    return Ok(true);
                }
                "fg" | "bg" => {
                    self.resume(argv.get(1), argv[0] == "fg")?;
                    return Ok(true);
                }
                "echo" | "pwd" | "cd" | "exit" => return super::run_command(line, None),
                program if program.ends_with(".app") => return super::run_command(line, None),
                _ => {}
            }
        }
        self.launch(&pipeline, line)?;
        Ok(true)
    }
    fn run(&mut self) -> io::Result<()> {
        let mut line = Vec::new();
        let mut discarding = false;
        super::print_prompt()?;
        while !HANGUP.load(Ordering::Relaxed) {
            self.refresh()?;
            super::drain_terminal_feedback()?;
            if INTERRUPTED.swap(false, Ordering::Relaxed) {
                line.clear();
                writeln!(io::stdout())?;
                super::print_prompt()?;
            }
            let mut event = libc::pollfd {
                fd: 0,
                events: libc::POLLIN,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut event, 1, 20) };
            if result < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(io::Error::last_os_error());
            }
            if result == 0 {
                continue;
            }
            let mut bytes = [0; 4096];
            let count = unsafe { libc::read(0, bytes.as_mut_ptr().cast(), bytes.len()) };
            if count < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(io::Error::last_os_error());
            }
            if count == 0 && line.is_empty() {
                break;
            }
            if INTERRUPTED.swap(false, Ordering::Relaxed) {
                line.clear();
                discarding = false;
                writeln!(io::stdout())?;
                super::print_prompt()?;
                continue;
            }
            if !discarding && line.len() + count as usize > 64 * 1024 {
                line.clear();
                discarding = true;
                writeln!(io::stderr(), "msh: command line is too long")?;
            }
            if discarding {
                if count == 0 || bytes[..count as usize].ends_with(b"\n") {
                    discarding = false;
                    super::print_prompt()?;
                }
                continue;
            }
            line.extend_from_slice(&bytes[..count as usize]);
            if count != 0 && !line.ends_with(b"\n") {
                continue;
            }
            match std::str::from_utf8(&line) {
                Ok(text) => match self.command(text.trim_end_matches(['\r', '\n'])) {
                    Ok(false) => break,
                    Ok(true) => {}
                    Err(error) => {
                        self.restore()?;
                        writeln!(io::stderr(), "msh: {error}")?;
                    }
                },
                Err(_) => writeln!(io::stderr(), "msh: command is not UTF-8")?,
            }
            line.clear();
            super::print_prompt()?;
        }
        Ok(())
    }
}
impl Drop for Shell {
    fn drop(&mut self) {
        for job in &self.jobs {
            let _ = job.notify(libc::SIGHUP);
            let _ = job.notify(libc::SIGCONT);
        }
        let _ = self.restore();
        let _ = unsafe { libc::tcsetattr(self.tty.as_raw_fd(), libc::TCSANOW, &self.original) };
    }
}
pub(crate) fn run(login: bool) -> io::Result<()> {
    Shell::new(login)?.run()
}
