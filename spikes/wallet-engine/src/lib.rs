//! Ticket 034 spike: wallet engine on rust-bitcoin + miniscript + bip39, no BDK.
//! Throwaway research code; never merged.

pub mod coinselection;
#[cfg(feature = "stack")]
pub mod keys;
#[cfg(feature = "stack")]
pub mod spend;

pub mod probe;
