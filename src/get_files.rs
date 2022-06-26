/*
use std::fs;
use std::io;
use std::path::Path;

fn read_dir<P: AsRef<Path>>(path: P) -> io::Result<Vec<String>> {
    println!("u");
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

fn get_files<P: AsRef<Path>>(path: P) -> io::Result<Vec<String>> {
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

fn get_files_to_provide(s: &str, group_number: u64) {

    let _dirs = read_dir(s);

    let mut dirs = _dirs.unwrap();

    let mut files = Vec::<String>::new();

    println!("{:?}", dirs);

    for dir in dirs {
        files.push(format!("{}.{}", dir, group_number));
    }

    println!("{:?}", files);
}

fn main() {
    get_files_to_provide("./bookshards", 1);
}

 */