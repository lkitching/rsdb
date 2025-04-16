use registers_macro::{syscalls};

include!("syscalls.inc");

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use super::{SyscallType};
    #[test]
    fn syscall_mapping_works() {
        assert_eq!(SyscallType::from_id(0).unwrap(), SyscallType::read);
        assert_eq!(SyscallType::from_str("read").unwrap(), SyscallType::read);
        assert_eq!(SyscallType::from_id(62).unwrap(), SyscallType::kill);
        assert_eq!(SyscallType::from_str("kill").unwrap(), SyscallType::kill);
    }
}