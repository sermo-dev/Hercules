//! Chain parameters: every consensus/network constant that differs between
//! mainnet and regtest, gathered in one place (ticket 027).
//!
//! Production code only ever sees `ChainParams::mainnet()`. `regtest()` is
//! compiled for tests only (`#[cfg(test)]`), so the shipped app can never be
//! pointed at a minimum-difficulty chain or have its peer-diversity rules
//! relaxed. The regtest instance exists so the sync integration harness can
//! mine valid blocks in microseconds and serve them from loopback mock peers.

use bitcoin::block::Header;
use bitcoin::p2p::Magic;
use bitcoin::Network;

use crate::assumeutxo::{SnapshotAnchor, MAINNET_ANCHOR, MIN_CHAIN_WORK};

// ── Script verification flags ────────────────────────────────────────
//
// Bit positions follow Bitcoin Core's `SCRIPT_VERIFY_*` enum
// (src/script/interpreter.h), which is also the ABI of
// libbitcoinconsensus. They are defined here rather than imported from the
// script library so the activation table below stays independent of which
// library verifies scripts (ticket 047 swaps it).

pub const SCRIPT_VERIFY_NONE: u32 = 0;
pub const SCRIPT_VERIFY_P2SH: u32 = 1 << 0;
pub const SCRIPT_VERIFY_DERSIG: u32 = 1 << 2;
pub const SCRIPT_VERIFY_NULLDUMMY: u32 = 1 << 4;
pub const SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY: u32 = 1 << 9;
pub const SCRIPT_VERIFY_CHECKSEQUENCEVERIFY: u32 = 1 << 10;
pub const SCRIPT_VERIFY_WITNESS: u32 = 1 << 11;
pub const SCRIPT_VERIFY_TAPROOT: u32 = 1 << 17;

/// Script flags that switch on at `height` (inclusive) and stay on.
#[derive(Debug, Clone, Copy)]
pub struct ScriptFlagActivation {
    pub height: u32,
    pub flags: u32,
}

/// Mainnet script-flag schedule. Reproduces exactly what
/// `bitcoinconsensus::height_to_flags` returned when it was the source of
/// truth (proved bit-for-bit at every boundary by
/// `mainnet_script_flags_match_height_to_flags`).
const MAINNET_SCRIPT_FLAGS: &[ScriptFlagActivation] = &[
    // BIP 16
    ScriptFlagActivation { height: 173_805, flags: SCRIPT_VERIFY_P2SH },
    // BIP 66
    ScriptFlagActivation { height: 363_725, flags: SCRIPT_VERIFY_DERSIG },
    // BIP 65
    ScriptFlagActivation { height: 388_381, flags: SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY },
    // BIP 112 (CSV)
    ScriptFlagActivation { height: 419_328, flags: SCRIPT_VERIFY_CHECKSEQUENCEVERIFY },
    // BIP 141/147 (SegWit + NULLDUMMY)
    ScriptFlagActivation {
        height: 481_824,
        flags: SCRIPT_VERIFY_NULLDUMMY | SCRIPT_VERIFY_WITNESS,
    },
    // BIP 341/342 (Taproot). `height_to_flags` used `height > 709_632`.
    ScriptFlagActivation { height: 709_633, flags: SCRIPT_VERIFY_TAPROOT },
];

/// Regtest: Core's regtest has every buried deployment active from height
/// 1 (BIP 65/66/CSV) or 0 (SegWit, Taproot always active).
#[cfg(test)]
const REGTEST_SCRIPT_FLAGS: &[ScriptFlagActivation] = &[
    ScriptFlagActivation {
        height: 0,
        flags: SCRIPT_VERIFY_P2SH
            | SCRIPT_VERIFY_NULLDUMMY
            | SCRIPT_VERIFY_WITNESS
            | SCRIPT_VERIFY_TAPROOT,
    },
    ScriptFlagActivation {
        height: 1,
        flags: SCRIPT_VERIFY_DERSIG
            | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
            | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    },
];

/// Consensus and network parameters for one chain.
#[derive(Debug, Clone, Copy)]
pub struct ChainParams {
    /// Which chain (also selects the genesis block via rust-bitcoin).
    pub network: Network,
    /// P2P message-start bytes.
    pub magic: Magic,
    /// Compact form of the highest allowed target (lowest difficulty).
    pub pow_limit_bits: u32,
    /// Regtest never retargets: every header keeps its parent's bits.
    pub no_retargeting: bool,
    /// Coinbase must encode the block height from this height on, and
    /// block versions below 2 are rejected (Core's `BIP34Height`).
    pub bip34_height: u32,
    /// Block versions below 3 are rejected from this height on
    /// (`BIP66Height`). The DERSIG script flag lives in the flag table.
    pub bip66_height: u32,
    /// Block versions below 4 are rejected from this height on
    /// (`BIP65Height`). The CLTV script flag lives in the flag table.
    pub bip65_height: u32,
    /// BIP 68 sequence locks and BIP 113 median-time-past locktime cutoff
    /// are enforced from this height on (`CSVHeight`, ticket 026). The
    /// BIP 112 script flag switches on at the same height in the flag table.
    pub csv_height: u32,
    /// Witness commitment is enforced from this height on.
    pub segwit_height: u32,
    /// Blocks between subsidy halvings.
    pub subsidy_halving_interval: u32,
    /// Script-flag activation schedule (see `script_flags`).
    pub script_flag_activations: &'static [ScriptFlagActivation],
    /// Minimum cumulative chainwork before the header chain is trusted
    /// (ticket 023). Zero on regtest.
    pub min_chain_work: [u8; 32],
    /// AssumeUTXO / chain anchor (ticket 023). `None` on regtest; the
    /// harness installs a test anchor when it needs one.
    pub anchor: Option<SnapshotAnchor>,
    /// Limit outbound peers to one per /16 (IPv4) or /32 (IPv6). Always on
    /// for mainnet; off on regtest because every mock peer is 127.0.0.1.
    pub enforce_netgroup_diversity: bool,
}

static MAINNET: ChainParams = ChainParams {
    network: Network::Bitcoin,
    magic: Magic::BITCOIN,
    pow_limit_bits: 0x1d00ffff,
    no_retargeting: false,
    bip34_height: 227_931,
    bip66_height: 363_725,
    bip65_height: 388_381,
    csv_height: 419_328,
    segwit_height: 481_824,
    subsidy_halving_interval: 210_000,
    script_flag_activations: MAINNET_SCRIPT_FLAGS,
    min_chain_work: MIN_CHAIN_WORK,
    anchor: Some(MAINNET_ANCHOR),
    enforce_netgroup_diversity: true,
};

#[cfg(test)]
static REGTEST: ChainParams = ChainParams {
    network: Network::Regtest,
    magic: Magic::REGTEST,
    pow_limit_bits: 0x207fffff,
    no_retargeting: true,
    // Core's regtest values (`CRegTestParams`): everything from height 1,
    // SegWit from 0.
    bip34_height: 1,
    bip66_height: 1,
    bip65_height: 1,
    csv_height: 1,
    segwit_height: 0,
    subsidy_halving_interval: 150,
    script_flag_activations: REGTEST_SCRIPT_FLAGS,
    min_chain_work: [0u8; 32],
    anchor: None,
    enforce_netgroup_diversity: false,
};

impl ChainParams {
    /// Bitcoin mainnet — the only chain production code can select.
    pub fn mainnet() -> &'static ChainParams {
        &MAINNET
    }

    /// Bitcoin regtest. Test-only.
    #[cfg(test)]
    pub fn regtest() -> &'static ChainParams {
        &REGTEST
    }

    /// Genesis block header (block 0).
    pub fn genesis_header(&self) -> Header {
        bitcoin::blockdata::constants::genesis_block(self.network).header
    }

    /// Script verification flags for a block at `height`.
    pub fn script_flags(&self, height: u32) -> u32 {
        self.script_flag_activations
            .iter()
            .filter(|a| height >= a.height)
            .fold(SCRIPT_VERIFY_NONE, |acc, a| acc | a.flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::deserialize;

    /// Every height at which a mainnet flag changes, plus the neighbours
    /// and the extremes.
    fn mainnet_probe_heights() -> Vec<u32> {
        let mut heights = vec![0, 1, u32::MAX - 1, u32::MAX];
        for a in MAINNET_SCRIPT_FLAGS {
            heights.extend([a.height - 1, a.height, a.height + 1]);
        }
        // Old `height_to_flags` boundaries, spelled out independently of
        // the table so a typo in the table can't hide itself.
        for h in [173_805u32, 363_725, 388_381, 419_328, 481_824, 709_632] {
            heights.extend([h - 1, h, h + 1]);
        }
        heights
    }

    #[test]
    fn mainnet_script_flags_match_height_to_flags() {
        let p = ChainParams::mainnet();
        for h in mainnet_probe_heights() {
            assert_eq!(
                p.script_flags(h),
                bitcoinconsensus::height_to_flags(h),
                "flag mismatch at height {}",
                h
            );
        }
        // Dense sweep around each boundary for good measure.
        for a in MAINNET_SCRIPT_FLAGS {
            for h in a.height.saturating_sub(50)..a.height + 50 {
                assert_eq!(p.script_flags(h), bitcoinconsensus::height_to_flags(h), "h={}", h);
            }
        }
    }

    #[test]
    fn script_flag_bits_match_libbitcoinconsensus_abi() {
        assert_eq!(SCRIPT_VERIFY_P2SH, bitcoinconsensus::VERIFY_P2SH);
        assert_eq!(SCRIPT_VERIFY_DERSIG, bitcoinconsensus::VERIFY_DERSIG);
        assert_eq!(SCRIPT_VERIFY_NULLDUMMY, bitcoinconsensus::VERIFY_NULLDUMMY);
        assert_eq!(
            SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
            bitcoinconsensus::VERIFY_CHECKLOCKTIMEVERIFY
        );
        assert_eq!(
            SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
            bitcoinconsensus::VERIFY_CHECKSEQUENCEVERIFY
        );
        assert_eq!(SCRIPT_VERIFY_WITNESS, bitcoinconsensus::VERIFY_WITNESS);
        assert_eq!(SCRIPT_VERIFY_TAPROOT, bitcoinconsensus::VERIFY_TAPROOT);
    }

    /// Library-independent statement of the mainnet schedule, so the table
    /// stays pinned after ticket 047 removes `height_to_flags`.
    #[test]
    fn mainnet_script_flags_explicit_values() {
        let p = ChainParams::mainnet();
        assert_eq!(p.script_flags(173_804), 0);
        assert_eq!(p.script_flags(173_805), 0x1);
        assert_eq!(p.script_flags(363_725), 0x5);
        assert_eq!(p.script_flags(388_381), 0x205);
        assert_eq!(p.script_flags(419_328), 0x605);
        assert_eq!(p.script_flags(481_824), 0xe15);
        assert_eq!(p.script_flags(709_632), 0xe15);
        assert_eq!(p.script_flags(709_633), 0x20e15);
    }

    #[test]
    fn mainnet_genesis_matches_previous_hardcoded_header() {
        let raw = hex::decode(
            "0100000000000000000000000000000000000000000000000000000000000000\
             000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa\
             4b1e5e4a29ab5f49ffff001d1dac2b7c",
        )
        .unwrap();
        let old: Header = deserialize(&raw).unwrap();
        assert_eq!(ChainParams::mainnet().genesis_header(), old);
    }

    #[test]
    fn mainnet_constants_unchanged() {
        let p = ChainParams::mainnet();
        assert_eq!(p.magic, Magic::BITCOIN);
        assert_eq!(p.pow_limit_bits, 0x1d00ffff);
        assert!(!p.no_retargeting);
        assert_eq!(p.bip34_height, 227_931);
        assert_eq!(p.bip66_height, 363_725);
        assert_eq!(p.bip65_height, 388_381);
        assert_eq!(p.csv_height, 419_328);
        assert_eq!(p.segwit_height, 481_824);
        assert_eq!(p.subsidy_halving_interval, 210_000);
        assert_eq!(p.min_chain_work, MIN_CHAIN_WORK);
        assert_eq!(p.anchor, Some(MAINNET_ANCHOR));
        assert!(p.enforce_netgroup_diversity);
    }

    /// The deployment heights used by the block-level rules (ticket 026)
    /// must agree with the script-flag table that switches on the matching
    /// script rule, on every chain.
    #[test]
    fn deployment_heights_match_script_flag_table() {
        for p in [ChainParams::mainnet(), ChainParams::regtest()] {
            for (height, flag) in [
                (p.bip66_height, SCRIPT_VERIFY_DERSIG),
                (p.bip65_height, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY),
                (p.csv_height, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY),
                (p.segwit_height, SCRIPT_VERIFY_WITNESS),
            ] {
                assert!(p.script_flags(height) & flag != 0, "{:?} flag {:#x} at {}", p.network, flag, height);
                if height > 0 {
                    assert!(
                        p.script_flags(height - 1) & flag == 0,
                        "{:?} flag {:#x} before {}",
                        p.network,
                        flag,
                        height
                    );
                }
            }
        }
    }

    #[test]
    fn regtest_genesis_hash() {
        assert_eq!(
            ChainParams::regtest().genesis_header().block_hash().to_string(),
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
        );
    }

    #[test]
    fn regtest_enables_everything_from_height_1() {
        let p = ChainParams::regtest();
        let all = SCRIPT_VERIFY_P2SH
            | SCRIPT_VERIFY_DERSIG
            | SCRIPT_VERIFY_NULLDUMMY
            | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
            | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
            | SCRIPT_VERIFY_WITNESS
            | SCRIPT_VERIFY_TAPROOT;
        assert_eq!(p.script_flags(1), all);
        assert_eq!(p.script_flags(1_000_000), all);
    }
}
