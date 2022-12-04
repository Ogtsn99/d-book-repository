use std::io;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub fn read_dir<P: AsRef<Path>>(path: P) -> io::Result<Vec<String>> {
    Ok(fs::read_dir(path)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            if entry.file_type().ok()?.is_dir() {
                Some(entry.file_name().to_string_lossy().into_owned())
            } else {
                None
            }
        })
        .collect())
}

pub fn get_files<P: AsRef<Path>>(path: P) -> io::Result<Vec<String>> {
    Ok(fs::read_dir(path)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            if entry.file_type().ok()?.is_file() {
                Some(entry.file_name().to_string_lossy().into_owned())
            } else {
                None
            }
        })
        .collect())
}

pub fn get_files_to_provide(s: &str, group_number: u64) {

    let _dirs = read_dir(s);

    let mut dirs = _dirs.unwrap();

    let mut files = Vec::<String>::new();

    println!("{:?}", dirs);

    for dir in dirs {
        files.push(format!("{}.{}", dir, group_number));
    }

    println!("{:?}", files);
}

pub fn get_file_as_byte_vec(filename: String) -> Vec<u8> {
    println!("{}", filename);
    let mut f = File::open(&filename).expect("no file found");
    let metadata = fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    buffer
}