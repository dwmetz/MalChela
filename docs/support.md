## 🦀 Support & Contribution

The MalChela project is open source and actively maintained. Contributions, feedback, and bug reports are always welcome. You can find the project on [GitHub](https://github.com/dwmetz/MalChela), where issues and pull requests are encouraged.

---

## Known Limitations & Platform Notes

MalChela is designed to be cross-platform but has some current limitations:

- The **CLI** runs well on macOS, Linux, and WSL environments.
- The **GUI** is supported on macOS and Linux. It may also work under WSLg on Windows 11, but this is not officially tested.
- File paths must use **POSIX-style formatting** (e.g., `/home/user/file.txt`). Windows-style paths are not supported.
- If the `exec_type` field is missing or misconfigured in `tools.yaml`, GUI execution may fail or behave incorrectly.
- The `category` field in `tools.yaml` no longer impacts GUI execution behavior—it is only used for grouping in the interface.

## iOS 26 Development Panic

If you're running iOS 26 beta and encounter a runtime panic like the following:

```
thread 'main' panicked at /Users/you/.cargo/registry/src/index.crates.io-*/icrate-0.0.4/.../NSEnumerator.rs:6:1: invalid message send ...
```

This is due to stricter signature checks in the Apple SDK when running in debug mode. The panic does **not** occur in release mode builds.

To avoid the crash, build and run in release mode:

```bash
cargo build --release
./target/release/MalChelaGUI
```

This issue does not affect normal usage or distribution of the application. Debug mode remains usable for building, but the GUI should be run from a release build on affected platforms.
