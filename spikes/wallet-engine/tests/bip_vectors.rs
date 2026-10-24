//! Spike step 1: BIP84 / BIP86 derivation, byte-for-byte against the official test vectors.
//!
//! Vectors copied verbatim from the BIP documents at bitcoin/bips
//! commit 24e96e870fffaa257b465ce1f0370c14aac588e8:
//!   https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0084.mediawiki#test-vectors
//!   https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0086.mediawiki#test-vectors

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpub};
use bitcoin::key::{TapTweak, XOnlyPublicKey};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, CompressedPublicKey, Network};
use miniscript::{Descriptor, ToPublicKey};
use wallet_engine_spike::keys::*;

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// ---- BIP84 ----------------------------------------------------------------------------
const BIP84_ROOTPRIV: &str = "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5";
const BIP84_ROOTPUB: &str = "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF";
const BIP84_ACCT_XPRV: &str = "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE";
const BIP84_ACCT_XPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
/// (chain, index, privkey WIF, pubkey, address)
const BIP84_ADDRS: [(u32, u32, &str, &str, &str); 3] = [
    (0, 0, "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d", "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
    (0, 1, "Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy", "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77", "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"),
    (1, 0, "KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF", "03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6", "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"),
];

#[test]
fn bip84_test_vectors() {
    let secp = Secp256k1::new();
    let master = master_from_mnemonic(MNEMONIC, "", Network::Bitcoin);
    assert_eq!(reencode_with_version(master.encode(), ZPRV_VERSION), BIP84_ROOTPRIV);
    assert_eq!(reencode_with_version(Xpub::from_priv(&secp, &master).encode(), ZPUB_VERSION), BIP84_ROOTPUB);

    let acct = Account::new(&secp, master, Purpose::Bip84, 0);
    assert_eq!(acct.account_path.to_string(), "84'/0'/0'");
    assert_eq!(reencode_with_version(acct.account_xprv.encode(), ZPRV_VERSION), BIP84_ACCT_XPRV);
    assert_eq!(reencode_with_version(acct.account_xpub.encode(), ZPUB_VERSION), BIP84_ACCT_XPUB);
    assert_eq!(acct.receive.to_string().split('#').next().unwrap(),
        format!("wpkh([73c5da0a/84'/0'/0']{}/0/*)", acct.account_xpub));

    for (chain, index, wif, pubkey, address) in BIP84_ADDRS {
        let path = DerivationPath::from_str(&format!("m/84'/0'/0'/{chain}/{index}")).unwrap();
        let sk = master.derive_priv(&secp, &path).unwrap().to_priv();
        assert_eq!(sk.to_wif(), wif);
        let pk = CompressedPublicKey::from_private_key(&secp, &sk).unwrap();
        assert_eq!(pk.to_string(), pubkey);
        // Address via the miniscript descriptor (the production path)...
        let addr = acct.address(chain, index, Network::Bitcoin);
        assert_eq!(addr.to_string(), address);
        // ...and via plain rust-bitcoin from the raw key, as a cross-check.
        assert_eq!(Address::p2wpkh(&pk, Network::Bitcoin).to_string(), address);
        assert_eq!(acct.at(chain, index).script_pubkey(), addr.script_pubkey());
    }
}

// ---- BIP86 ----------------------------------------------------------------------------
const BIP86_ROOTPRIV: &str = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";
const BIP86_ROOTPUB: &str = "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8";
const BIP86_ACCT_XPRV: &str = "xprv9xgqHN7yz9MwCkxsBPN5qetuNdQSUttZNKw1dcYTV4mkaAFiBVGQziHs3NRSWMkCzvgjEe3n9xV8oYywvM8at9yRqyaZVz6TYYhX98VjsUk";
const BIP86_ACCT_XPUB: &str = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";

struct Bip86Addr {
    chain: u32,
    index: u32,
    xprv: &'static str,
    xpub: &'static str,
    internal_key: &'static str,
    output_key: &'static str,
    script_pubkey: &'static str,
    address: &'static str,
}

const BIP86_ADDRS: [Bip86Addr; 3] = [
    Bip86Addr {
        chain: 0, index: 0,
        xprv: "xprvA449goEeU9okwCzzZaxiy475EQGQzBkc65su82nXEvcwzfSskb2hAt2WymrjyRL6kpbVTGL3cKtp9herYXSjjQ1j4stsXXiRF7kXkCacK3T",
        xpub: "xpub6H3W6JmYJXN49h5TfcVjLC3onS6uPeUTTJoVvRC8oG9vsTn2J8LwigLzq5tHbrwAzH9DGo6ThGUdWsqce8dGfwHVBxSbixjDADGGdzF7t2B",
        internal_key: "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        output_key: "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
        script_pubkey: "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
        address: "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
    },
    Bip86Addr {
        chain: 0, index: 1,
        xprv: "xprvA449goEeU9okyiF1LmKiDaTgeXvmh87DVyRd35VPbsSop8n8uALpbtrUhUXByPFKK7C2yuqrB1FrhiDkEMC4RGmA5KTwsE1aB5jRu9zHsuQ",
        xpub: "xpub6H3W6JmYJXN4CCKUSnriaiQRCZmG6aq4sCMDqTu1ACyngw7HShf59hAxYjXgKDuuHThVEUzdHrc3aXCr9kfvQvZPit5dnD3K9xVRBzjK3rX",
        internal_key: "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145",
        output_key: "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
        script_pubkey: "5120a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
        address: "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
    },
    Bip86Addr {
        chain: 1, index: 0,
        xprv: "xprvA3Ln3Gt3aphvUgzgEDT8vE2cYqb4PjFfpmbiFKphxLg1FjXQpkAk5M1ZKDY15bmCAHA35jTiawbFuwGtbDZogKF1WfjwxML4gK7WfYW5JRP",
        xpub: "xpub6GL8SnQwRCGDhB59LEz9HMyM6sRYoByXBzXK3iEKWgCz8XrZNHUzd9L3AUBELW5NzA7dEFvMas1F84TuPH3xqdUA5tumaGWFgihJzWytXe3",
        internal_key: "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef",
        output_key: "882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc",
        script_pubkey: "5120882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc",
        address: "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
    },
];

#[test]
fn bip86_test_vectors() {
    let secp = Secp256k1::new();
    let master = master_from_mnemonic(MNEMONIC, "", Network::Bitcoin);
    assert_eq!(master.to_string(), BIP86_ROOTPRIV);
    assert_eq!(Xpub::from_priv(&secp, &master).to_string(), BIP86_ROOTPUB);

    let acct = Account::new(&secp, master, Purpose::Bip86, 0);
    assert_eq!(acct.account_xprv.to_string(), BIP86_ACCT_XPRV);
    assert_eq!(acct.account_xpub.to_string(), BIP86_ACCT_XPUB);

    for v in BIP86_ADDRS {
        let path = DerivationPath::from_str(&format!("m/86'/0'/0'/{}/{}", v.chain, v.index)).unwrap();
        let xprv = master.derive_priv(&secp, &path).unwrap();
        assert_eq!(xprv.to_string(), v.xprv);
        assert_eq!(Xpub::from_priv(&secp, &xprv).to_string(), v.xpub);

        let desc = acct.at(v.chain, v.index);
        let Descriptor::Tr(tr) = &desc else { panic!("expected tr()") };
        let internal: XOnlyPublicKey = tr.internal_key().to_public_key().into();
        assert_eq!(internal.to_string(), v.internal_key);
        // BIP86: no script tree, tweak with empty merkle root.
        let (output, _): (bitcoin::key::TweakedPublicKey, _) = internal.tap_tweak(&secp, None);
        assert_eq!(output.to_string(), v.output_key);
        assert_eq!(desc.script_pubkey().to_hex_string(), v.script_pubkey);
        assert_eq!(acct.address(v.chain, v.index, Network::Bitcoin).to_string(), v.address);
    }
}

/// Not in the spec docs as a vector, but pins the descriptor checksum / origin format we
/// would persist, so later refactors can't silently change a stored wallet's descriptors.
#[test]
fn descriptors_round_trip() {
    let secp = Secp256k1::new();
    let master = master_from_mnemonic(MNEMONIC, "", Network::Bitcoin);
    for p in [Purpose::Bip44, Purpose::Bip84, Purpose::Bip86] {
        let acct = Account::new(&secp, master, p, 0);
        let s = acct.receive.to_string();
        assert!(s.contains('#'), "checksum present: {s}");
        let parsed: Descriptor<miniscript::DescriptorPublicKey> = s.parse().unwrap();
        assert_eq!(parsed, acct.receive);
    }
    // BIP44 pkh(): descriptor address == plain rust-bitcoin P2PKH from the derived key.
    let acct44 = Account::new(&secp, master, Purpose::Bip44, 0);
    let sk = master.derive_priv(&secp, &DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap()).unwrap().to_priv();
    let pk = bitcoin::PublicKey::from_private_key(&secp, &sk);
    assert_eq!(acct44.address(0, 0, Network::Bitcoin), Address::p2pkh(pk, Network::Bitcoin));
}
