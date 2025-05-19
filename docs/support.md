
## 🦀 Support & Contribution

	•	GitHub: https://github.com/dwmetz/MalChela
	•	Issues/PRs welcome
	•	Extend via tools.yaml for external tools



### ⚠️ Known Limitations & WSL Notes

	•	CLI works in WSL
	•	GUI requires macOS or Linux (may work in WSLg on Win11)
	•	Paths must be POSIX-style
	•	If `exec_type` is omitted or misconfigured in `tools.yaml`, the GUI may attempt to run the tool incorrectly.
	•	GUI execution behavior no longer depends on the `category` field.
	•	FLOSS may print a warning such as `from multiprocessing.resource_tracker import main;main(6)` due to a known bug in its multiprocessing logic. This does not affect output and can be safely ignored.
