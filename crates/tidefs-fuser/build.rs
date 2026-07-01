fn main() {
    println!("cargo:rustc-check-cfg=cfg(fuser_libfuse2)");
    println!("cargo:rustc-check-cfg=cfg(fuser_libfuse3)");

    #[cfg(all(not(feature = "libfuse"), not(target_os = "linux")))]
    panic!("Building without libfuse is only supported on Linux");

    #[cfg(feature = "libfuse")]
    {
        #[cfg(target_os = "macos")]
        {
            if pkg_config::Config::new()
                .atleast_version("2.6.0")
                .probe("fuse") // for macFUSE 4.x
                .map_err(|e| eprintln!("{}", e))
                .is_ok()
            {
                println!("cargo:rustc-cfg=fuser_libfuse2");
            } else {
                pkg_config::Config::new()
                    .atleast_version("2.6.0")
                    .probe("osxfuse") // for osxfuse 3.x
                    .map_err(|e| eprintln!("{}", e))
                    .expect("Failed to find osxfuse via pkg-config");
                println!("cargo:rustc-cfg=fuser_libfuse2");
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            // First try to link with libfuse3
            if pkg_config::Config::new()
                .atleast_version("3.0.0")
                .probe("fuse3")
                .map_err(|e| eprintln!("{e}"))
                .is_ok()
            {
                println!("cargo:rustc-cfg=fuser_libfuse3");
            } else {
                // Fallback to libfuse
                pkg_config::Config::new()
                    .atleast_version("2.6.0")
                    .probe("fuse")
                    .map_err(|e| eprintln!("{e}"))
                    .expect("Failed to find fuse via pkg-config");
                println!("cargo:rustc-cfg=fuser_libfuse2");
            }
        }
    }
}
