//! Keys and descriptors: BIP39 mnemonic -> BIP32 master -> BIP84 / BIP86 / BIP44 account
//! descriptors (miniscript) -> addresses.
//!
//! Nothing here implements cryptography or script logic; it only wires `bip39`,
//! `bitcoin::bip32` and `miniscript::Descriptor` together.

use std::str::FromStr;

use bitcoin::base58;
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{Address, Network};
use miniscript::descriptor::{DefiniteDescriptorKey, Descriptor, DescriptorPublicKey};

/// Script type of an account. Maps 1:1 to a BIP43 purpose and a descriptor template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// BIP44, P2PKH, `pkh()`
    Bip44,
    /// BIP84, P2WPKH, `wpkh()`
    Bip84,
    /// BIP86, P2TR key-path only, `tr()`
    Bip86,
}

impl Purpose {
    pub fn number(self) -> u32 {
        match self {
            Purpose::Bip44 => 44,
            Purpose::Bip84 => 84,
            Purpose::Bip86 => 86,
        }
    }
    fn wrap(self, key: &str) -> String {
        match self {
            Purpose::Bip44 => format!("pkh({key})"),
            Purpose::Bip84 => format!("wpkh({key})"),
            Purpose::Bip86 => format!("tr({key})"),
        }
    }
}

/// BIP39 mnemonic (+ optional passphrase) -> BIP32 master key.
pub fn master_from_mnemonic(words: &str, passphrase: &str, network: Network) -> Xpriv {
    let mnemonic = bip39::Mnemonic::parse_normalized(words).expect("valid BIP39 mnemonic");
    let seed = mnemonic.to_seed_normalized(passphrase);
    Xpriv::new_master(network, &seed).expect("seed is 64 bytes")
}

/// One BIP43-style account: `m/purpose'/coin'/account'`.
pub struct Account {
    pub purpose: Purpose,
    pub master: Xpriv,
    pub account_path: DerivationPath,
    pub account_xprv: Xpriv,
    pub account_xpub: Xpub,
    /// `<purpose>([fp/purpose'/coin'/account']xpub/0/*)`
    pub receive: Descriptor<DescriptorPublicKey>,
    /// `<purpose>([fp/purpose'/coin'/account']xpub/1/*)`
    pub change: Descriptor<DescriptorPublicKey>,
}

impl Account {
    pub fn new(secp: &Secp256k1<All>, master: Xpriv, purpose: Purpose, account: u32) -> Self {
        let coin = if master.network == bitcoin::NetworkKind::Main { 0 } else { 1 };
        let account_path =
            DerivationPath::from_str(&format!("m/{}'/{coin}'/{account}'", purpose.number()))
                .unwrap();
        let account_xprv = master.derive_priv(secp, &account_path).unwrap();
        let account_xpub = Xpub::from_priv(secp, &account_xprv);
        let fp = master.fingerprint(secp);
        let origin = account_path.to_string(); // "m/84'/0'/0'"
        let origin = origin.trim_start_matches("m/");
        let mk = |chain: u32| -> Descriptor<DescriptorPublicKey> {
            let key = format!("[{fp}/{origin}]{account_xpub}/{chain}/*");
            Descriptor::from_str(&purpose.wrap(&key)).expect("valid descriptor")
        };
        let receive = mk(0);
        let change = mk(1);
        Account { purpose, master, account_path, account_xprv, account_xpub, receive, change }
    }

    /// Definite (wildcard-free) descriptor for `chain` (0 = receive, 1 = change) at `index`.
    pub fn at(&self, chain: u32, index: u32) -> Descriptor<DefiniteDescriptorKey> {
        let d = if chain == 0 { &self.receive } else { &self.change };
        d.at_derivation_index(index).expect("non-hardened index")
    }

    pub fn address(&self, chain: u32, index: u32, network: Network) -> Address {
        self.at(chain, index).address(network).expect("descriptor has an address form")
    }
}

/// SLIP-132 version bytes (BIP84 test vectors are written as zprv/zpub).
pub const ZPRV_VERSION: [u8; 4] = [0x04, 0xb2, 0x43, 0x0c];
pub const ZPUB_VERSION: [u8; 4] = [0x04, 0xb2, 0x47, 0x46];

/// Re-encode an extended key with different version bytes (presentation only; the key
/// material is untouched). Used to compare against BIP84's zprv/zpub vectors.
pub fn reencode_with_version(mut raw: [u8; 78], version: [u8; 4]) -> String {
    raw[..4].copy_from_slice(&version);
    base58::encode_check(&raw)
}
