//! unpack — static packer detection and unpacking for PE, ELF, and Mach-O.
//!
//! Static only: nothing here executes or emulates the sample. Where a packer
//! can only be removed by running its stub (Themida, VMProtect, custom
//! crypters), unpack identifies it, records the evidence, and says so.

pub mod binfmt;
pub mod detect;
pub mod dotnet;
pub mod engine;
pub mod external;
pub mod pyc;
pub mod pyinstaller;
pub mod report;
pub mod upx;
pub mod util;

pub use detect::packer_summary;
