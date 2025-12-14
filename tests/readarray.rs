use srmilter::{array_contains, read_array};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_read_array() {
    let mut file1 = NamedTempFile::new().unwrap();
    file1
        .write_all(b"\n\nTest1\n  Test2  \n\n# ignore\nTest3  # ignore\n")
        .unwrap();
    let array = read_array(file1.path().to_str().unwrap()).unwrap();
    assert_eq!(array, ["Test1", "Test2", "Test3"]);
    assert_eq!(array_contains(&array, "Bla"), false);
    assert_eq!(array_contains(&array, "Test1"), true);
    assert_eq!(array_contains(&array, "Test3"), true);
    assert_eq!(array_contains(&array, "xTest2"), false);
    assert_eq!(array_contains(&array, "Test2x"), false);
}
