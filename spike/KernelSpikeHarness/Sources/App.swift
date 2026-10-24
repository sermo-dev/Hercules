// Spike 047 harness: runs the kernel-spike benches in-process on the device
// and prints JSON to the console (Xcode debug area / `simctl launch --console`).
// Launch argument `-autorun` runs both benches immediately at launch, which is
// the closest we get to a "cold wake" measurement (process just started).
import SwiftUI

/// Kernel-recorded process start time (so "ms after launch" includes dyld + static init).
func processStartDate() -> Date {
    var kinfo = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
    sysctl(&mib, 4, &kinfo, &size, nil, 0)
    let tv = kinfo.kp_proc.p_un.__p_starttime
    return Date(timeIntervalSince1970: Double(tv.tv_sec) + Double(tv.tv_usec) / 1e6)
}
let processStart = processStartDate()

func runBench(_ name: String) -> String {
    let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].path
    let testdata = Bundle.main.resourceURL!.appendingPathComponent("testdata").path
    let t = Date()
    let ptr: UnsafeMutablePointer<CChar>? = name == "bench"
        ? kernel_spike_run_bench(caches) : kernel_spike_run_verify(testdata)
    let s = String(cString: ptr!)
    kernel_spike_free_string(ptr)
    let wall = Date().timeIntervalSince(t) * 1000
    let sinceLaunch = t.timeIntervalSince(processStart) * 1000
    let out = "KERNEL_SPIKE \(name) wall_ms=\(Int(wall)) started_ms_after_launch=\(Int(sinceLaunch)) \(s)"
    print(out)
    fflush(stdout)
    // Also append to Documents/kernel-spike-results.txt (Xcode > Devices > Download Container).
    let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    let file = docs.appendingPathComponent("kernel-spike-results.txt")
    if !FileManager.default.fileExists(atPath: file.path) { FileManager.default.createFile(atPath: file.path, contents: nil) }
    if let h = try? FileHandle(forWritingTo: file) { h.seekToEndOfFile(); h.write((out + "\n").data(using: .utf8)!); try? h.close() }
    return out
}

@main
struct HarnessApp: App {
    init() {
        if CommandLine.arguments.contains("-autorun") {
            _ = runBench("bench")
            _ = runBench("verify")
            print("KERNEL_SPIKE done"); fflush(stdout)
        }
    }
    var body: some Scene { WindowGroup { ContentView() } }
}

struct ContentView: View {
    @State private var output = "Tap a button. Results are also printed to the console."
    @State private var busy = false
    var body: some View {
        VStack(spacing: 12) {
            Text("Ticket 047 kernel spike").font(.headline)
            HStack {
                Button("Chainstate bench") { run("bench") }
                Button("Script verify bench") { run("verify") }
            }.disabled(busy)
            ScrollView { Text(output).font(.system(size: 10, design: .monospaced)).textSelection(.enabled) }
        }.padding()
    }
    func run(_ name: String) {
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            let r = runBench(name)
            DispatchQueue.main.async { output = r; busy = false }
        }
    }
}
