//! Runs every Step-1 script-verification case through the ONE engine this
//! binary links (feature `kernel` or `consensus`): TSV on stdout, JSON summary
//! (timings, mismatches vs Core's expected results) on stderr.
//! run-step1.sh builds it twice and diffs the TSVs.
//!
//!   verify-dump <testdata dir>
fn main() {
    let dir = std::env::args().nth(1).expect("usage: verify-dump <testdata dir>");
    let (tsv, summary) = kernel_spike::step1::run(std::path::Path::new(&dir));
    print!("{tsv}");
    eprintln!("{}", serde_json::to_string_pretty(&summary).unwrap());
}
