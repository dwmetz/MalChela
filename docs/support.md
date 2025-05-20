
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
