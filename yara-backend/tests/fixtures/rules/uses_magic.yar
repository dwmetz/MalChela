// Uses the libyara-only `magic` module. yara-x does not implement
// magic, so the audit pass refuses this file with UnsupportedModule
// before it ever reaches the engine.
import "magic"

rule magic_user {
    condition:
        magic.type() contains "ELF"
}
