use std::ffi::CString;

#[derive(Clone)]
pub struct IrisPolicy {
    file_paths_read: Vec<CString>,
    file_paths_write: Vec<CString>,
}

impl IrisPolicy {
    pub fn new() -> Self {
        Self {
            file_paths_read: Vec::new(),
            file_paths_write: Vec::new(),
        }
    }

    pub fn allow_file_path_for_read(&mut self, path: &CString) -> Result<(), String> {
        self.file_paths_read.push(path.to_owned());
        Ok(())
    }

    pub fn is_file_path_allowed_for_read(&self, path: &CString) -> bool {
        self.file_paths_read.contains(&path.to_owned())
    }

    pub fn allow_file_path_for_write(&mut self, path: &CString) -> Result<(), String> {
        self.file_paths_write.push(path.to_owned());
        Ok(())
    }

    pub fn is_file_path_allowed_for_write(&self, path: &CString) -> bool {
        self.file_paths_write.contains(&path.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use crate::IrisPolicy;
    use std::ffi::CString;

    #[test]
    fn works() {
        let mut pol = IrisPolicy::new();
        pol.allow_file_path_for_read(&CString::new("/etc/hosts").unwrap()).expect("Unable to allow path");
        assert!(pol.is_file_path_allowed_for_read(&CString::new("/etc/hosts").unwrap()));
        assert!(!pol.is_file_path_allowed_for_read(&CString::new("/etc/resolv.conf").unwrap()));
    }
}
