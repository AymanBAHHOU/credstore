//! `credstore-sandbox`: starts an approved command inside the Windows AppContainer
//! (M12). The daemon runs it in place of the command; see
//! `credstore-os/src/sys/windows/appcontainer.rs`.

fn main() {
    std::process::exit(credstore_os::sandbox::launcher_main());
}
