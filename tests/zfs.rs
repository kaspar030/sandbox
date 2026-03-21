//! ZFS storage backend integration tests.
//!
//! These tests require a ZFS pool to be available. They are ignored by default
//! and run only when `--include-ignored` is passed (e.g., in the privileged
//! Docker test or on the testhost).
//!
//! To run manually:
//!   1. Set up a ZFS pool (see scripts/bootstrap-testhost-zfs.sh)
//!   2. Set SANDBOX_ZFS_POOL=/path/to/zfs/mountpoint
//!   3. cargo test --test zfs -- --include-ignored

mod common;

use sandbox::storage::fs_detect::FsType;
use sandbox::storage::zfs;
use std::path::PathBuf;
use std::process::Command;

/// Get the ZFS test pool path from env, or skip.
fn zfs_pool_path() -> Option<PathBuf> {
    std::env::var("SANDBOX_ZFS_POOL").ok().map(PathBuf::from)
}

/// Check if we're on a system with ZFS available.
fn has_zfs() -> bool {
    Command::new("zfs")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Create a unique test directory path under the ZFS pool.
fn test_dir(pool: &std::path::Path, name: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    pool.join(format!("zfs-test-{name}-{ts}"))
}

#[test]
#[ignore]
fn test_zfs_detect_filesystem() {
    let pool = match zfs_pool_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: SANDBOX_ZFS_POOL not set");
            return;
        }
    };

    let fs_type =
        sandbox::storage::fs_detect::detect_filesystem(&pool).expect("detect_filesystem failed");
    assert_eq!(fs_type, FsType::Zfs, "expected ZFS filesystem at {pool:?}");
    assert!(fs_type.supports_snapshots());
    assert!(fs_type.supports_idmap());
    assert_eq!(fs_type.name(), "zfs");
}

#[test]
#[ignore]
fn test_zfs_dataset_create_destroy() {
    let pool = match zfs_pool_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: SANDBOX_ZFS_POOL not set");
            return;
        }
    };

    let test_path = test_dir(&pool, "create");

    // Create dataset
    zfs::zfs_dataset_create(&test_path).expect("zfs_dataset_create failed");
    assert!(test_path.is_dir(), "dataset should be mounted as directory");

    // Write a file into it
    std::fs::write(test_path.join("hello.txt"), "world").expect("write failed");
    assert!(test_path.join("hello.txt").exists());

    // Destroy dataset
    zfs::zfs_dataset_destroy(&test_path).expect("zfs_dataset_destroy failed");
    assert!(
        !test_path.exists(),
        "directory should be gone after destroy"
    );
}

#[test]
#[ignore]
fn test_zfs_clone() {
    let pool = match zfs_pool_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: SANDBOX_ZFS_POOL not set");
            return;
        }
    };

    let source_path = test_dir(&pool, "clone-src");
    let dest_path = test_dir(&pool, "clone-dst");

    // Create source dataset with content
    zfs::zfs_dataset_create(&source_path).expect("create source failed");
    std::fs::write(source_path.join("data.txt"), "original content").expect("write failed");
    std::fs::create_dir_all(source_path.join("subdir")).expect("mkdir failed");
    std::fs::write(source_path.join("subdir/nested.txt"), "nested").expect("write failed");

    // Clone it
    zfs::zfs_clone(&source_path, &dest_path).expect("zfs_clone failed");
    assert!(dest_path.is_dir(), "clone should be mounted");

    // Verify content is present in clone
    assert_eq!(
        std::fs::read_to_string(dest_path.join("data.txt")).unwrap(),
        "original content"
    );
    assert_eq!(
        std::fs::read_to_string(dest_path.join("subdir/nested.txt")).unwrap(),
        "nested"
    );

    // Modify clone — should not affect source (CoW)
    std::fs::write(dest_path.join("data.txt"), "modified in clone").expect("write failed");
    assert_eq!(
        std::fs::read_to_string(source_path.join("data.txt")).unwrap(),
        "original content",
        "source should be unmodified after clone write"
    );

    // Clean up (order matters: clone first, then source)
    zfs::zfs_dataset_destroy(&dest_path).expect("destroy clone failed");
    zfs::zfs_dataset_destroy(&source_path).expect("destroy source failed");
}

#[test]
#[ignore]
fn test_zfs_path_to_dataset() {
    let pool = match zfs_pool_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: SANDBOX_ZFS_POOL not set");
            return;
        }
    };

    // The pool root should resolve to a dataset
    let dataset = zfs::path_to_dataset(&pool).expect("path_to_dataset failed for pool root");
    assert!(!dataset.is_empty(), "dataset name should not be empty");

    // A child path should include the relative components
    let child = pool.join("some/nested/path");
    let child_dataset =
        zfs::path_to_dataset(&child).expect("path_to_dataset failed for child path");
    assert!(
        child_dataset.ends_with("/some/nested/path"),
        "child dataset '{}' should end with relative path",
        child_dataset
    );
    assert!(
        child_dataset.starts_with(&dataset),
        "child dataset '{}' should start with pool dataset '{}'",
        child_dataset,
        dataset
    );
}

#[test]
#[ignore]
fn test_zfs_exclusive_size() {
    let pool = match zfs_pool_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: SANDBOX_ZFS_POOL not set");
            return;
        }
    };

    let test_path = test_dir(&pool, "size");
    zfs::zfs_dataset_create(&test_path).expect("create failed");

    // Write some data
    std::fs::write(test_path.join("bigfile"), vec![0u8; 1024 * 1024]).expect("write failed");

    // Check size
    let size = zfs::zfs_exclusive_size(&test_path);
    assert!(size.is_some(), "should be able to get size of ZFS dataset");
    assert!(size.unwrap() > 0, "size should be > 0 after writing data");

    // Clean up
    zfs::zfs_dataset_destroy(&test_path).expect("destroy failed");
}

#[test]
#[ignore]
fn test_zfs_container_rootfs_lifecycle() {
    use sandbox::storage::StoragePool;
    use sandbox::storage::container_fs;

    let pool_mount = match zfs_pool_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: SANDBOX_ZFS_POOL not set");
            return;
        }
    };

    // Create a test area that simulates a storage pool
    let test_base = test_dir(&pool_mount, "lifecycle");
    zfs::zfs_dataset_create(&test_base).expect("create test base");

    let images_dir = test_base.join("images");
    let fs_dir = test_base.join("fs");
    zfs::zfs_dataset_create(&images_dir).expect("create images dir");
    zfs::zfs_dataset_create(&fs_dir).expect("create fs dir");

    // Create a fake image
    let image_path = images_dir.join("testimg");
    zfs::zfs_dataset_create(&image_path).expect("create image dataset");
    std::fs::write(image_path.join("hello"), "from image").expect("write image content");

    let pool = StoragePool {
        name: "zfs-test".to_string(),
        path: test_base.clone(),
        fs_type: FsType::Zfs,
    };

    // Create container rootfs from image
    let container_path = container_fs::create_container_rootfs(&pool, "testimg", "container1")
        .expect("create_container_rootfs failed");

    assert!(container_path.is_dir());
    assert_eq!(
        std::fs::read_to_string(container_path.join("hello")).unwrap(),
        "from image"
    );

    // Modify container — should not affect image
    std::fs::write(container_path.join("hello"), "modified").unwrap();
    assert_eq!(
        std::fs::read_to_string(image_path.join("hello")).unwrap(),
        "from image"
    );

    // Destroy container rootfs
    container_fs::destroy_container_rootfs(&pool, "container1")
        .expect("destroy_container_rootfs failed");
    assert!(!pool.container_path("container1").exists());

    // Clean up
    zfs::zfs_dataset_destroy(&test_base).expect("destroy test base");
}

#[test]
#[ignore]
fn test_zfs_snapshot_container_to_image() {
    use sandbox::storage::StoragePool;
    use sandbox::storage::container_fs;

    let pool_mount = match zfs_pool_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: SANDBOX_ZFS_POOL not set");
            return;
        }
    };

    let test_base = test_dir(&pool_mount, "snapshot");
    zfs::zfs_dataset_create(&test_base).expect("create test base");

    let images_dir = test_base.join("images");
    let fs_dir = test_base.join("fs");
    zfs::zfs_dataset_create(&images_dir).expect("create images dir");
    zfs::zfs_dataset_create(&fs_dir).expect("create fs dir");

    // Create source image and container
    let image_path = images_dir.join("srcimg");
    zfs::zfs_dataset_create(&image_path).expect("create source image");
    std::fs::write(image_path.join("base"), "base content").unwrap();

    let pool = StoragePool {
        name: "zfs-snap".to_string(),
        path: test_base.clone(),
        fs_type: FsType::Zfs,
    };

    let container_path = container_fs::create_container_rootfs(&pool, "srcimg", "mycontainer")
        .expect("create container");

    // Modify container
    std::fs::write(container_path.join("extra"), "new file").unwrap();

    // Snapshot container as new image
    container_fs::snapshot_container_to_image(&pool, "mycontainer", "newimg", false)
        .expect("snapshot_container_to_image failed");

    let new_image_path = images_dir.join("newimg");
    assert!(new_image_path.is_dir());
    assert_eq!(
        std::fs::read_to_string(new_image_path.join("base")).unwrap(),
        "base content"
    );
    assert_eq!(
        std::fs::read_to_string(new_image_path.join("extra")).unwrap(),
        "new file"
    );

    // Clean up
    zfs::zfs_dataset_destroy(&test_base).expect("destroy test base");
}

#[test]
#[ignore]
fn test_zfs_volume_create_remove() {
    use sandbox::storage::StoragePool;
    use sandbox::storage::volume;

    let pool_mount = match zfs_pool_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: SANDBOX_ZFS_POOL not set");
            return;
        }
    };

    let test_base = test_dir(&pool_mount, "volumes");
    zfs::zfs_dataset_create(&test_base).expect("create test base");

    let volumes_dir = test_base.join("volumes");
    zfs::zfs_dataset_create(&volumes_dir).expect("create volumes dir");

    let pool = StoragePool {
        name: "zfs-vol".to_string(),
        path: test_base.clone(),
        fs_type: FsType::Zfs,
    };

    // Create volume
    volume::create_volume(&pool, "testvol").expect("create_volume failed");
    let vol_path = volume::volume_path(&pool, "testvol");
    assert!(vol_path.is_dir());

    // Write data
    std::fs::write(vol_path.join("data"), "persistent").unwrap();

    // List volumes
    let vols = volume::list_volumes(&pool).expect("list_volumes failed");
    assert!(vols.iter().any(|v| v.name == "testvol"));

    // Remove volume
    volume::remove_volume(&pool, "testvol").expect("remove_volume failed");
    assert!(!vol_path.exists());

    // Clean up
    zfs::zfs_dataset_destroy(&test_base).expect("destroy test base");
}

#[test]
fn test_zfs_fs_type_properties() {
    // This test doesn't need ZFS — it tests the enum properties
    assert!(FsType::Zfs.supports_snapshots());
    assert!(FsType::Zfs.supports_idmap());
    assert_eq!(FsType::Zfs.name(), "zfs");
    assert_eq!(format!("{}", FsType::Zfs), "zfs");
}

#[test]
fn test_zfs_check_snapshot_tool() {
    use sandbox::storage::container_fs::check_snapshot_tool;
    // On a system with zfs installed, this should return true
    // On a system without zfs, this should return false
    // Either way, it shouldn't panic
    let result = check_snapshot_tool(&FsType::Zfs);
    if has_zfs() {
        assert!(result, "zfs tool should be found when ZFS is installed");
    }
}
