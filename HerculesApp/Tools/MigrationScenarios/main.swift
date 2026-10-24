import Foundation
let fm = FileManager.default
func mk(_ root: URL) -> StoragePaths.Layout {
    try? fm.removeItem(at: root)
    let docs = root.appendingPathComponent("Documents"), sup = root.appendingPathComponent("Support")
    try! fm.createDirectory(at: docs, withIntermediateDirectories: true)
    try! fm.createDirectory(at: sup.appendingPathComponent("Chain"), withIntermediateDirectories: true)
    return StoragePaths.Layout(documents: docs, applicationSupport: sup)
}
func put(_ dir: URL, _ name: String, _ body: String) {
    if name == "utxo-lmdb" { try! fm.createDirectory(at: dir.appendingPathComponent(name), withIntermediateDirectories: true)
        try! body.write(to: dir.appendingPathComponent(name).appendingPathComponent("data.mdb"), atomically: true, encoding: .utf8); return }
    try! body.write(to: dir.appendingPathComponent(name), atomically: true, encoding: .utf8)
}
func read(_ dir: URL, _ name: String) -> String? {
    let u = name == "utxo-lmdb" ? dir.appendingPathComponent(name).appendingPathComponent("data.mdb") : dir.appendingPathComponent(name)
    return try? String(contentsOf: u, encoding: .utf8)
}
func parked(_ l: StoragePaths.Layout) -> [String] { ((try? fm.contentsOfDirectory(atPath: l.conflictDir.path)) ?? []).sorted() }
var fails = 0
func check(_ c: Bool, _ msg: String) { print((c ? "PASS " : "FAIL ") + msg); if !c { fails += 1 } }
let base = URL(fileURLWithPath: CommandLine.arguments[1])
let H = "hercules-headers.sqlite3"

// 1. clean legacy layout moves everything
var l = mk(base.appendingPathComponent("s1"))
for n in [H, H+"-wal", H+"-shm", "utxo-lmdb", "utxo-lmdb.loading", "own_txs.sqlite3", "tor"] { put(l.documents, n, "doc-"+n) }
try! StoragePaths.migrate(l)
check([H, H+"-wal", H+"-shm", "utxo-lmdb", "utxo-lmdb.loading", "own_txs.sqlite3", "tor"].allSatisfy { read(l.chainDir, $0) == "doc-"+$0 }, "s1 all moved intact")
check(parked(l).isEmpty && fm.fileExists(atPath: l.markerURL.path), "s1 nothing parked, marker written")

// 2. downgrade conflict on sqlite: Chain primary wins, Documents primary+wal parked together
l = mk(base.appendingPathComponent("s2"))
put(l.chainDir, "peers.sqlite3", "chain-peers")
put(l.documents, "peers.sqlite3", "doc-peers"); put(l.documents, "peers.sqlite3-wal", "doc-wal")
try! StoragePaths.migrate(l)
check(read(l.chainDir, "peers.sqlite3") == "chain-peers", "s2 chain primary untouched")
check(read(l.chainDir, "peers.sqlite3-wal") == nil, "s2 foreign -wal NOT placed next to chain primary")
check(parked(l).count == 2, "s2 both documents files parked: \(parked(l))")

// 3. utxo conflict: stray .loading must not land next to a valid env
l = mk(base.appendingPathComponent("s3"))
put(l.chainDir, "utxo-lmdb", "chain-utxo")
put(l.documents, "utxo-lmdb", "doc-utxo"); put(l.documents, "utxo-lmdb.loading", "x")
try! StoragePaths.migrate(l)
check(read(l.chainDir, "utxo-lmdb") == "chain-utxo" && !fm.fileExists(atPath: l.chainDir.appendingPathComponent("utxo-lmdb.loading").path), "s3 valid env kept, no .loading in Chain")
check(parked(l).count == 2, "s3 env + sentinel parked: \(parked(l))")

// 4. interrupted migration (companion moved, primary not): resumes
l = mk(base.appendingPathComponent("s4"))
put(l.chainDir, H+"-wal", "doc-wal")
put(l.documents, H, "doc-h"); put(l.documents, H+"-shm", "doc-shm")
try! StoragePaths.migrate(l)
check(read(l.chainDir, H) == "doc-h" && read(l.chainDir, H+"-wal") == "doc-wal" && read(l.chainDir, H+"-shm") == "doc-shm", "s4 group completed")
check(parked(l).isEmpty, "s4 nothing parked")

// 5. stale companion in Chain, live pair in Documents: stale parked, live pair moved
l = mk(base.appendingPathComponent("s5"))
put(l.chainDir, "blocks.sqlite3-wal", "stale-wal")
put(l.documents, "blocks.sqlite3", "live-db"); put(l.documents, "blocks.sqlite3-wal", "live-wal")
try! StoragePaths.migrate(l)
check(read(l.chainDir, "blocks.sqlite3") == "live-db" && read(l.chainDir, "blocks.sqlite3-wal") == "live-wal", "s5 live pair together in Chain")
check(parked(l).count == 1 && parked(l)[0].contains(".stale."), "s5 stale companion parked: \(parked(l))")

// 6. idempotent rerun
let before = (try! fm.subpathsOfDirectory(atPath: l.chainDir.path)).sorted()
try! StoragePaths.migrate(l)
check((try! fm.subpathsOfDirectory(atPath: l.chainDir.path)).sorted() == before, "s6 rerun changes nothing")
print(fails == 0 ? "ALL PASS" : "\(fails) FAILED"); exit(fails == 0 ? 0 : 1)
