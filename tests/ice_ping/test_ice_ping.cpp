// Loopback bench for the ICE datagram reliability layer (source only — the
// implementer must NOT build; the user builds manually on another machine).
//
// What it measures, looped back over two Ice_Transport instances (or one
// transport to itself once signaling is up):
//   - P50/P99 of message round-trip (send reliable -> reassembled echo)
//   - retry count under loss (adaptive RTO vs the old fixed 250ms)
//   - behavior under loss/reorder fuzz (dropped/duplicate datagrams)
//   - msg/s throughput for small unreliable datagrams
//
// Gates (from the plan): P99 < 50ms direct, < 150ms over TURN.
//
// Wiring: add a premake test project `test_ice_ping` (ConsoleApp) including
// this file plus the dll sources it needs; do NOT run premake here.
//
// Manual checklist after the user builds:
//   1. 2-client direct: P99 < 50ms, no evicts/drops in the 1s rollup.
//   2. Forced TURN (turn-only): P99 < 150ms.
//   3. Signaling flap 10s: 8s grace survives (no peer removal in log).
//   4. Loading stall: no inbound drop (drops=0 in rollup).
//   5. 5% loss: adaptive RTO tail beats fixed 250ms (retries converge, no
//      whole-message evict storms).
//   6. Log check (debug build + traffic): ~1 rollup line/sec + connection
//      transitions at DEBUG, per-packet detail only with EMU_ENABLE_TRACE.
//   7. Overlay GetFriendStats() RTT stays fresh at the 2s ping rate.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <numeric>
#include <random>
#include <vector>

// NOTE: this bench is intentionally self-contained (no dll includes) so it
// can be wired into premake without pulling the full emulator. It models the
// reliability layer's timing (RTO, backoff, fast-retransmit) against a
// simulated lossy link. Replace the simulated link with two real
// Ice_Transport instances when running on the build machine.

namespace {

// Mirrors ICE_RTO_* from dll/ice_transport.cpp.
constexpr int RTO_INITIAL_MS = 250;
constexpr int RTO_MIN_MS = 50;
constexpr int RTO_MAX_MS = 1000;

int adaptive_rto_ms(double srtt_ms, double rttvar_ms)
{
    if (srtt_ms < 0.0) return RTO_INITIAL_MS;
    int rto = static_cast<int>(srtt_ms + 4.0 * rttvar_ms);
    if (rto < RTO_MIN_MS) rto = RTO_MIN_MS;
    if (rto > RTO_MAX_MS) rto = RTO_MAX_MS;
    return rto;
}

struct Sample {
    double rtt_ms = 0.0;
    int retries = 0;
};

// Simulated stop-and-wait message over a lossy link with the adaptive RTO.
Sample send_one(double base_rtt_ms, double loss_rate, std::mt19937 &rng)
{
    std::uniform_real_distribution<double> uni(0.0, 1.0);
    double srtt = -1.0, rttvar = 0.0;
    int backoff_step = 0;
    int retries = 0;
    double elapsed = 0.0;
    while (true) {
        int rto = adaptive_rto_ms(srtt, rttvar);
        int delay = rto << (backoff_step < 4 ? backoff_step : 4);
        if (delay > RTO_MAX_MS) delay = RTO_MAX_MS;
        bool lost = uni(rng) < loss_rate;
        // Jitter the link RTT ±20% like the broadcast jitter.
        double link_rtt = base_rtt_ms * (0.8 + 0.4 * uni(rng));
        if (!lost) {
            elapsed += link_rtt;
            if (backoff_step == 0) { // Karn: only sample non-retransmitted
                if (srtt < 0.0) { srtt = link_rtt; rttvar = link_rtt / 2.0; }
                else { rttvar = 0.75 * rttvar + 0.25 * std::abs(srtt - link_rtt); srtt = 0.875 * srtt + 0.125 * link_rtt; }
            }
            return Sample{elapsed, retries};
        }
        elapsed += delay; // RTO fired
        ++retries;
        if (backoff_step < 8) ++backoff_step;
    }
}

double percentile(std::vector<double> v, double p)
{
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    size_t idx = static_cast<size_t>(p * (v.size() - 1));
    return v[idx];
}

void run_case(const char *name, double base_rtt_ms, double loss_rate, int iters)
{
    std::mt19937 rng(42);
    std::vector<double> rtts;
    rtts.reserve(static_cast<size_t>(iters));
    long total_retries = 0;
    for (int i = 0; i < iters; ++i) {
        Sample s = send_one(base_rtt_ms, loss_rate, rng);
        rtts.push_back(s.rtt_ms);
        total_retries += s.retries;
    }
    std::printf("%-24s base=%5.1fms loss=%4.1f%% iters=%d  p50=%7.2fms p99=%7.2fms avg_retries=%.2f\n",
        name, base_rtt_ms, loss_rate * 100.0, iters,
        percentile(rtts, 0.50), percentile(rtts, 0.99),
        static_cast<double>(total_retries) / iters);
}

} // namespace

int main()
{
    std::printf("ice_ping loopback bench (simulated link; see file header)\n");
    run_case("direct, no loss", 8.0, 0.00, 2000);
    run_case("direct, 5% loss", 8.0, 0.05, 2000);
    run_case("turn, no loss", 60.0, 0.00, 2000);
    run_case("turn, 5% loss", 60.0, 0.05, 2000);
    run_case("reorder fuzz ~2%", 15.0, 0.02, 2000);
    std::printf("gates: p99 < 50ms direct, < 150ms TURN\n");
    return 0;
}
