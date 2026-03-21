//! Bcachefs storage backend integration tests.
//!
//! These tests require a bcachefs filesystem to be available. They are
//! ignored by default and run only when `--include-ignored` is passed.
//!
//! To run manually:
//!   1. Set up a bcachefs pool (see scripts/bootstrap-testhost-bcachefs.sh)
//!   2. Set SANDBOX_BCACHEFS_POOL=/path/to/bcachefs/mountpoint
//!   3. cargo test --test bcachefs -- --include-ignored

mod common;

use sandbox::storage::container_fs;
use sandbox::storage::fs_detect::FsType;
use std::path::PathBuf;
use std::process::Command;

/// Get the bcachefs test pool path from env, or skip.
fn bcachefs_pool_path() -> Option<PathBuf> {
    std::env::var("SANDBOX_BCACHEFS_POOL")
        .ok()
        .map(PathBuf::from)
}

/// Check if we're on a system with the bcachefs CLI available.
fn has_bcachefs() -> bool {
    Command::new("bcachefs")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Create a unique test directory path under the bcachefs pool.
fn test_dir(pool: &std::path::Path, name: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    pool.join(format!("bcachefs-test-{name}-{ts}"))
}

#[test]
#[ignore]
fn test_bcachefs_detect_filesystem() {
    let pool = match bcachefs_pool_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: SANDBOX_BCACHEFS_POOL not set");
            return;
        }
    };

    let fs_type =
        sandbox::storage::fs_detect::detect_filesystem(&pool).expect("detect_filesystem failed");
    assert_eq!(
        fs_type,
        FsType::Bcachefs,
        "expected bcachefs filesystem at {pool:?}"
    );
    assert!(fs_type.supports_snapshots());
    assert!(fs_type.supports_idmap());
    assert_eq!(fs_type.name(), "bcachefs");
}

#[test]
#[ignore]
fn test_bcachefs_subvolume_create_destroy() {
    let pool = match bcachefs_pool_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: SANDBOX_BCACHEFS_POOL not set");
            return;
        }
    };

    let test_path = test_dir(&pool, "create");

    // Create subvolume
    container_fs::bcachefs_subvolume_create(&test_path).expect("subvolume create failed");
    assert!(test_path.is_dir(), "subvolume should be a directory");

    // Write a file into it
    std::fs::write(test_path.join("hello.txt"), "world").expect("write failed");
    assert!(test_path.join("hello.txt").exists());

    // Destroy subvolume
    container_fs::bcachefs_subvolume_delete(&test_path).expect("subvolume delete failed");
    assert!(!test_path.exists(), "directory should be gone after delete");
}

#[test]
#[ignore]
fn test_bcachefs_snapshot() {
    let pool = match bcachefs_pool_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: SANDBOX_BCACHEFS_POOL not set");
            return;
        }
    };

    let source_path = test_dir(&pool, "snap-src");
    let dest_path = test_dir(&pool, "snap-dst");

    // Create source subvolume with content
    container_fs::bcachefs_subvolume_create(&source_path).expect("create source failed");
    std::fs::write(source_path.join("data.txt"), "original content").expect("write failed");
    std::fs::create_dir_all(source_path.join("subdir")).expect("mkdir failed");
    std::fs::write(source_path.join("subdir/nested.txt"), "nested").expect("write failed");

    // Snapshot it
    let status = Command::new("bcachefs")
        .args(["subvolume", "snapshot"])
        .arg(&source_path)
        .arg(&dest_path)
        .status()
        .expect("failed to run bcachefs snapshot");
    assert!(status.success(), "bcachefs snapshot failed");
    assert!(dest_path.is_dir(), "snapshot should be mounted");

    // Verify content is present in snapshot
    assert_eq!(
        std::fs::read_to_string(dest_path.join("data.txt")).unwrap(),
        "original content"
    );
    assert_eq!(
        std::fs::read_to_string(dest_path.join("subdir/nested.txt")).unwrap(),
        "nested"
    );

    // Modify snapshot — should not affect source (CoW)
    std::fs::write(dest_path.join("data.txt"), "modified in snapshot").expect("write failed");
    assert_eq!(
        std::fs::read_to_string(source_path.join("data.txt")).unwrap(),
        "original content",
        "source should be unmodified after snapshot write"
    );

    // Clean up
    container_fs::bcachefs_subvolume_delete(&dest_path).expect("delete snapshot failed");
    container_fs::bcachefs_subvolume_delete(&source_path).expect("delete source failed");
}

#[test]
#[ignore]
fn test_bcachefs_container_rootfs_lifecycle() {
    use sandbox::storage::StoragePool;

    let pool_mount = match bcachefs_pool_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: SANDBOX_BCACHEFS_POOL not set");
            return;
        }
    };

    // Create a test area that simulates a storage pool
    let test_base = test_dir(&pool_mount, "lifecycle");
    std::fs::create_dir_all(&test_base).expect("create test base");

    let images_dir = test_base.join("images");
    let fs_dir = test_base.join("fs");
    std::fs::create_dir_all(&images_dir).expect("create images dir");
    std::fs::create_dir_all(&fs_dir).expect("create fs dir");

    // Create a fake image as a subvolume
    let image_path = images_dir.join("testimg");
    container_fs::bcachefs_subvolume_create(&image_path).expect("create image subvolume");
    std::fs::write(image_path.join("hello"), "from image").expect("write image content");

    let pool = StoragePool {
        name: "bcachefs-test".to_string(),
        path: test_base.clone(),
        fs_type: FsType::Bcachefs,
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
    container_fs::bcachefs_subvolume_delete(&image_path).expect("delete image");
    let _ = std::fs::remove_dir_all(&test_base);
}

#[test]
#[ignore]
fn test_bcachefs_snapshot_container_to_image() {
    use sandbox::storage::StoragePool;

    let pool_mount = match bcachefs_pool_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: SANDBOX_BCACHEFS_POOL not set");
            return;
        }
    };

    let test_base = test_dir(&pool_mount, "snapshot");
    std::fs::create_dir_all(&test_base).expect("create test base");

    let images_dir = test_base.join("images");
    let fs_dir = test_base.join("fs");
    std::fs::create_dir_all(&images_dir).expect("create images dir");
    std::fs::create_dir_all(&fs_dir).expect("create fs dir");

    // Create source image and container
    let image_path = images_dir.join("srcimg");
    container_fs::bcachefs_subvolume_create(&image_path).expect("create source image");
    std::fs::write(image_path.join("base"), "base content").unwrap();

    let pool = StoragePool {
        name: "bcachefs-snap".to_string(),
        path: test_base.clone(),
        fs_type: FsType::Bcachefs,
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
    container_fs::bcachefs_subvolume_delete(&new_image_path).expect("delete new image");
    container_fs::bcachefs_subvolume_delete(&container_path).expect("delete container");
    container_fs::bcachefs_subvolume_delete(&image_path).expect("delete source image");
    let _ = std::fs::remove_dir_all(&test_base);
}

#[test]
#[ignore]
fn test_bcachefs_volume_create_remove() {
    use sandbox::storage::StoragePool;
    use sandbox::storage::volume;

    let pool_mount = match bcachefs_pool_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: SANDBOX_BCACHEFS_POOL not set");
            return;
        }
    };

    let test_base = test_dir(&pool_mount, "volumes");
    std::fs::create_dir_all(&test_base).expect("create test base");

    let volumes_dir = test_base.join("volumes");
    std::fs::create_dir_all(&volumes_dir).expect("create volumes dir");

    let pool = StoragePool {
        name: "bcachefs-vol".to_string(),
        path: test_base.clone(),
        fs_type: FsType::Bcachefs,
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
    let _ = std::fs::remove_dir_all(&test_base);
}

#[test]
fn test_bcachefs_fs_type_properties() {
    // This test doesn't need bcachefs — it tests the enum properties
    assert!(FsType::Bcachefs.supports_snapshots());
    assert!(FsType::Bcachefs.supports_idmap());
    assert_eq!(FsType::Bcachefs.name(), "bcachefs");
    assert_eq!(format!("{}", FsType::Bcachefs), "bcachefs");
}

#[test]
fn test_bcachefs_check_snapshot_tool() {
    let result = container_fs::check_snapshot_tool(&FsType::Bcachefs);
    if has_bcachefs() {
        assert!(
            result,
            "bcachefs tool should be found when bcachefs is installed"
        );
    }
}
