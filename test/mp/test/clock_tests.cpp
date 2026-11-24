// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mp/proxy-io.h>
#include <mp/proxy.h>

#include <capnp/common.h>
#include <kj/async-io.h>
#include <kj/common.h>
#include <kj/debug.h>
#include <kj/function.h>
#include <kj/memory.h>
#include <kj/test.h>
#include <kj/time.h>
#include <kj/timer.h>
#include <kj/units.h>

#include <cstdlib>
#include <ctime>
#include <dlfcn.h>
#include <future>
#include <string>
#include <sys/types.h>
#include <thread>

namespace {
struct ClockRegression
{
    timespec time{};
    unsigned reads{0};
    std::promise<void> entering_wait;
};

// Only the event-loop thread opts into the fake clock. In particular, CTest's
// watchdog and the test thread's synchronization keep using the real clock.
thread_local ClockRegression* g_regression{nullptr};
} // namespace

// Interpose both KJ's clock reads and calls from this executable, without
// requiring LD_PRELOAD or a modified Cap'n Proto build.
extern "C" int clock_gettime(clockid_t clock, struct timespec* time) noexcept
{
    if (clock == CLOCK_MONOTONIC && g_regression) {
        *time = g_regression->time;
        if (++g_regression->reads == 1) g_regression->entering_wait.set_value();
        return 0;
    }
    static const auto real_clock_gettime =
        reinterpret_cast<decltype(&clock_gettime)>(dlsym(RTLD_NEXT, "clock_gettime"));
    if (!real_clock_gettime) std::abort();
    return real_clock_gettime(clock, time);
}

KJ_TEST("EventLoop recovers from a backward monotonic clock reading")
{
    ClockRegression regression;
    unsigned warnings{0};
    std::promise<mp::EventLoopRef> started;
    std::thread thread([&] {
        mp::EventLoop loop("mpclocktest", [&](mp::LogMessage log) {
            if (log.level == mp::Log::Warning &&
                log.message.find("non-monotonic clock read") != std::string::npos) ++warnings;
        });
        started.set_value(mp::EventLoopRef{loop});
        loop.loop();
    });
    auto loop = started.get_future().get();

    loop->sync([&] {
        // Regress relative to KJ's last observed time, so scheduling delays
        // cannot cause the real clock to catch up before the fault is observed.
        const auto time = loop->m_io_context.provider->getTimer().now() -
            kj::origin<kj::TimePoint>() - 10 * kj::MILLISECONDS;
        regression.time.tv_sec = time / kj::SECONDS;
        regression.time.tv_nsec = (time % kj::SECONDS) / kj::NANOSECONDS;
        g_regression = &regression;
    });

    // KJ reads the clock before entering epoll_wait(), and again after waking.
    // Wait for the first read before posting work: this ensures the socket read
    // is pending, instead of completing synchronously and bypassing KJ's timer.
    regression.entering_wait.get_future().wait();
    loop->sync([&] { g_regression = nullptr; });

    // Check another callback and clean shutdown after restoring the real clock.
    bool completed{false};
    loop->sync([&] { completed = true; });
    loop.reset();
    thread.join();

    KJ_EXPECT(regression.reads >= 2);
    KJ_EXPECT(completed);
#if CAPNP_VERSION < 1002000
    // Older KJ versions rely on ClockErrorCallback, which runs each time KJ
    // advances its timer while the fake clock is behind, so it can run more
    // than once.
    KJ_EXPECT(warnings >= 1);
#else
    // Newer KJ versions clamp the time internally.
    KJ_EXPECT(warnings == 0);
#endif
}
