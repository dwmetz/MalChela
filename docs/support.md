## Support & Contribution

The MalChela project is open source and actively maintained. Contributions, feedback, and bug reports are always welcome. You can find the project on [GitHub](https://github.com/dwmetz/MalChela), where issues and pull requests are encouraged.

---

## Known Limitations & Platform Notes

MalChela is designed to be cross-platform but has some current limitations:

- The **CLI** runs well on macOS, Linux, and WSL environments.
- The **web interface** runs on any platform with a browser. Start the server with `python server/malchela_server.py` and open `http://localhost:8675`.
- File paths must use **POSIX-style formatting** (e.g., `/home/user/file.txt`). Windows-style paths are not supported.
- If the `exec_type` field is missing or misconfigured in `tools.yaml`, web interface execution may fail or behave incorrectly.
- The `category` field in `tools.yaml` no longer impacts web interface execution behavior—it is only used for grouping in the interface.
