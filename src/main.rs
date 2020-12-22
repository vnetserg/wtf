use nix::sys::ptrace;
use nix::sys::signal::{
    kill,
    Signal,
};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{
    execvp,
    fork,
    ForkResult,
    getpid,
    Pid,
};

use std::env;
use std::ffi::{CStr, CString, OsStr};
use std::path::Path;
use std::process::exit;
use std::os::unix::ffi::OsStrExt;

const SYS_OPEN: u64 = 2;
const SYS_OPENAT: u64 = 257;
const MAX_PATH_LENGTH: usize = 4096;
const WORD_SIZE: usize = 4;

fn run_child(args: Vec<String>) {
    ptrace::traceme().expect("traceme() failed");
    kill(getpid(), Signal::SIGSTOP).expect("sending sigstop failed");

    let args: Vec<&CStr> = args.into_iter()
        .skip(1)
        .map(|s| Box::leak(CString::new(s).unwrap().into_boxed_c_str()) as &CStr)
        .collect();

    execvp(&args[0], &args[0..]).unwrap();
}

fn run_parent(child: Pid) {
    match waitpid(child, None).expect("waitpid() failed") {
        WaitStatus::Stopped { .. } => (),
        status => panic!(format!("Unexpected waitpid() status: {:?}", status)),
    }

    ptrace::setoptions(child, ptrace::Options::PTRACE_O_TRACESYSGOOD).expect("setoptions() failed");

    let mut orig_path = [0u8; MAX_PATH_LENGTH];

    while wait_for_open(child) {
        let path = read_path(child, &mut orig_path);

        eprintln!("Open: {}", path.to_string_lossy());

        if !wait_for_open(child) {
            break;
        }
    }
}

fn wait_for_open(child: Pid) -> bool {
    loop {
        ptrace::syscall(child, None).expect("syscall() failed");

        match waitpid(child, None).expect("waitpid() failed") {
            WaitStatus::PtraceSyscall(..) => {
                let syscall_number = ptrace::getregs(child)
                    .expect("getregs() failed")
                    .orig_rax;
                if syscall_number == SYS_OPEN || syscall_number == SYS_OPENAT {
                    return true;
                }
            }
            WaitStatus::Exited(..) => return false,
            _ => (),
        }
    }
}

fn read_path<'a>(child: Pid, buffer: &'a mut [u8]) -> &'a Path {
    let regs = ptrace::getregs(child)
        .expect("getregs() failed");

    let address = match regs.orig_rax {
        SYS_OPEN => regs.rdi,
        SYS_OPENAT => regs.rsi,
        _ => unreachable!(),
    } as usize;

    for base in (0..buffer.len()).step_by(WORD_SIZE) {
        let word = ptrace::read(child, (address + base) as *mut _)
            .expect("read() failed");

        for i in 0..WORD_SIZE {
            let byte: u8 = ((word >> (8 * i)) & 0xff) as u8;
            if byte == 0 {
                return Path::new(OsStr::from_bytes(&buffer[..base + i]));
            }

            buffer[base + i] = byte;
        }
    }

    return Path::new(OsStr::from_bytes(&buffer[..]));
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} program [args...]", args[0]);
        exit(1);
    }
    
    match fork().expect("fork() failed") {
        ForkResult::Parent { child, .. } => run_parent(child),
        ForkResult::Child => run_child(args),
    }
}
