import Foundation

final class Token: WakeCancellable {
    private let lock = NSLock()
    private var n = 0
    func cancel() { lock.lock(); n += 1; lock.unlock() }
    var cancels: Int { lock.lock(); defer { lock.unlock() }; return n }
}
var fails = 0
func check(_ c: Bool, _ msg: String) { print((c ? "PASS " : "FAIL ") + msg); if !c { fails += 1 } }

// 1. no foreground session: the wake runs, nothing to preempt
var s = NodeSessionState()
var t = Token()
check(s.admitWake(t, appInForeground: true) == .run(preemptsForeground: false), "s1 idle node: wake runs")
s.finishWake(t, stoppedForegroundSync: false)
check(s.inFlightWakes == 0, "s1 wake deregistered")

// 2. app on screen and syncing: the wake leaves it to foreground
s = NodeSessionState(); s.beginForeground()
t = Token()
check(s.admitWake(t, appInForeground: true) == .foregroundActive, "s2 foreground active: wake skipped")
check(s.inFlightWakes == 0, "s2 skipped wake not registered")
check(s.endForeground() == false, "s2 foreground not marked preempted")

// 3. sync left running in the background: the wake preempts it, and the
//    sync loop returning before the wake does still sees the preemption
s = NodeSessionState(); s.beginForeground()
t = Token()
check(s.admitWake(t, appInForeground: false) == .run(preemptsForeground: true), "s3 background sync: wake preempts")
check(s.endForeground() == true, "s3 sync returning mid-wake is told to restart")
s.finishWake(t, stoppedForegroundSync: true)
check(!s.isForegroundActive && s.inFlightWakes == 0, "s3 clean afterwards")

// 4. Rust didn't have to stop a sync (session between Rust calls, e.g.
//    snapshot download): nothing to restart
s = NodeSessionState(); s.beginForeground()
t = Token()
_ = s.admitWake(t, appInForeground: false)
s.finishWake(t, stoppedForegroundSync: false)
check(s.endForeground() == false, "s4 no restart when the loop wasn't stopped")

// 5. foreground starting cancels in-flight wakes, once each
s = NodeSessionState()
let a = Token(), b = Token()
_ = s.admitWake(a, appInForeground: false); _ = s.admitWake(b, appInForeground: false)
s.beginForeground()
check(a.cancels == 1 && b.cancels == 1, "s5 both wakes cancelled by foreground start")
s.finishWake(a, stoppedForegroundSync: false); s.finishWake(b, stoppedForegroundSync: false)
check(s.endForeground() == false, "s5 foreground start clears stale preemption")

// 6. overlapping foreground sessions (stop then quick restart)
s = NodeSessionState(); s.beginForeground(); s.beginForeground()
_ = s.endForeground()
check(s.isForegroundActive, "s6 still active while the second session runs")
t = Token()
check(s.admitWake(t, appInForeground: true) == .foregroundActive, "s6 wake still skipped")
_ = s.endForeground()
check(!s.isForegroundActive, "s6 inactive after both end")
check(s.endForeground() == false && !s.isForegroundActive, "s6 extra end doesn't underflow")

// 7. discard (reset) cancels every in-flight wake
s = NodeSessionState()
let c = Token()
_ = s.admitWake(c, appInForeground: false)
s.cancelAllWakes()
check(c.cancels == 1, "s7 discard cancels wakes")

// 8. OnceGate: watchdog, expiration and Rust's return racing; exactly one wins
for round in 0..<200 {
    let gate = OnceGate()
    let lock = NSLock()
    var calls = 0, wins = 0
    DispatchQueue.concurrentPerform(iterations: 3) { _ in
        if gate.fire({ lock.lock(); calls += 1; lock.unlock() }) {
            lock.lock(); wins += 1; lock.unlock()
        }
    }
    if calls != 1 || wins != 1 { check(false, "s8 round \(round): \(calls) calls, \(wins) wins"); break }
    if round == 199 { check(true, "s8 completion handler called exactly once in 200 racing rounds") }
}

// 9. concurrent admissions and finishes leave the bookkeeping consistent
s = NodeSessionState(); s.beginForeground()
let tokens = (0..<64).map { _ in Token() }
DispatchQueue.concurrentPerform(iterations: tokens.count) { i in
    _ = s.admitWake(tokens[i], appInForeground: false)
    s.finishWake(tokens[i], stoppedForegroundSync: i == 0)
}
check(s.inFlightWakes == 0, "s9 every wake deregistered")
_ = s.endForeground()
check(!s.isForegroundActive, "s9 foreground ended")

// 10. a wake cancelled by foreground starting is attributed to it (so its
//     record says "foreground", not "ran out of time"); others are not
s = NodeSessionState()
let early = Token(), late = Token()
_ = s.admitWake(early, appInForeground: false)
s.beginForeground()
check(s.finishWake(early, stoppedForegroundSync: false) == .foregroundStarted, "s10 wake cancelled by foreground start is attributed")
_ = s.endForeground()
_ = s.admitWake(late, appInForeground: false)
check(s.finishWake(late, stoppedForegroundSync: false) == .none, "s10 later wake not attributed")
let reset = Token()
_ = s.admitWake(reset, appInForeground: false)
s.cancelAllWakes()
check(s.finishWake(reset, stoppedForegroundSync: false) == .reset && reset.cancels == 1, "s10 reset cancel is attributed to the reset")

// 11. a wake-stopped session restarts whether its loop returned cleanly or
//     errored (dead sockets after suspension); a user Stop never restarts
check(ForegroundRestart.decide(preempted: true, userStopped: false, appInForeground: false) == .whenActive, "s11 preempted in background: restart when active")
check(ForegroundRestart.decide(preempted: true, userStopped: false, appInForeground: true) == .now, "s11 preempted, back on screen: restart now")
check(ForegroundRestart.decide(preempted: true, userStopped: true, appInForeground: true) == .none, "s11 user stop wins over preemption")
check(ForegroundRestart.decide(preempted: false, userStopped: false, appInForeground: true) == .none, "s11 plain error: no restart")
// the error path: a session that ended in an error still reports the preemption
s = NodeSessionState(); s.beginForeground()
let w = Token()
_ = s.admitWake(w, appInForeground: false)
let preempted = s.endForeground() // the loop errored out mid-wake
s.finishWake(w, stoppedForegroundSync: true)
check(ForegroundRestart.decide(preempted: preempted, userStopped: false, appInForeground: false) == .whenActive, "s11 errored preempted session is restarted")

// 12. session tokens: stop and retire are visible across threads
let tok = SyncSessionToken(generation: 3)
check(!tok.isOver && !tok.ended, "s12 fresh token")
DispatchQueue.global().sync { tok.stop() }
check(tok.stopped && tok.isOver && !tok.retired, "s12 stopped")
let tok2 = SyncSessionToken(generation: 4)
DispatchQueue.global().sync { tok2.retire(); tok2.markEnded() }
check(tok2.retired && tok2.isOver && tok2.ended, "s12 retired and ended")

// 13. history survives a downgrade: unknown sources decode, a bad record is
//     dropped alone, an unparseable file is nil (never overwritten)
let good = #"{"id":"6F9619FF-8B86-D011-B42D-00C04FC964FF","height":5,"blockHash":"h","timestamp":0,"timestampHuman":"","validated":true,"headerValidated":true,"receivedAt":0,"source":"fullValidation","validationError":null}"#
let future = good.replacingOccurrences(of: "fullValidation", with: "someFutureSource")
    .replacingOccurrences(of: "6F9619FF", with: "7F9619FF")
let broken = #"{"id":"nope"}"#
let decoded = NotificationHistory.decode(Data("[\(good),\(future),\(broken)]".utf8))
check(decoded?.count == 2, "s13 good + future record kept, broken one dropped: \(decoded?.count ?? -1)")
check(decoded?.last?.source == .unknown, "s13 unknown source decodes as .unknown")
check(NotificationHistory.decode(Data("not json".utf8)) == nil, "s13 unparseable file is nil, not []")

print(fails == 0 ? "ALL PASS" : "\(fails) FAILED")
exit(fails == 0 ? 0 : 1)
