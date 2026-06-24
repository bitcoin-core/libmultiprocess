// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://opensource.org.
#include "unixlistener.h"
#include <kj/async.h>
#include <kj/common.h>
#include <kj/debug.h>
#include <kj/memory.h>
#include <kj/test.h>
#include <mp/proxy.h>
#include <mp/proxy-io.h>
#include <mp/test/foo.capnp.h>
#include <mp/test/foo.capnp.proxy.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring> // IWYU pragma: keep
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <thread>

namespace mp {
namespace test {
namespace {

//! Default event loop log handler used by tests, throws so the calling code
//! can assert on errors.
void DefaultLogHandler(mp::LogMessage log)
{
    if (log.level == mp::Log::Raise)
        throw std::runtime_error(log.message);
}

class TestSetup
{
public:
    int client_fd;
    int server_fd;

    mp::EventLoop* loop;
    std::optional<mp::EventLoopRef> loop_ref;
    //! Thread variable should be after other struct members so the thread does
    //! not start until the other members are initialized.
    std::thread loop_thread;

    TestSetup(mp::LogFn log_handler = DefaultLogHandler)
        : TestSetup(
              [](int fds[2]) {
                  KJ_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != -1);
              },
              log_handler) {}

    TestSetup(const std::function<void(int[2])>& init_sockets,
              mp::LogFn log_handler = DefaultLogHandler)
    {
        std::promise<mp::EventLoop*> loop_promise;
        loop_thread = std::thread([&, log_handler] {
            mp::EventLoop loop("mptest-connect", log_handler);
            loop_promise.set_value(&loop);
            loop.loop();
        });
        loop = loop_promise.get_future().get();
        loop_ref.emplace(*loop);

        // Initialize and store sockets
        int fds[2] = {-1, -1};
        init_sockets(fds);

        client_fd = fds[0];
        server_fd = fds[1];
    }

    ~TestSetup()
    {
        loop_ref.reset();
        loop_thread.join();
    }
};

KJ_TEST("ConnectStream connects to a socket serving a valid init interface")
{
    TestSetup setup;

    std::thread server_thread([&setup]() {
        mp::EventLoop server_loop("mptest-valid-server", DefaultLogHandler);
        std::unique_ptr<FooInit> init = std::make_unique<FooInit>();
        ServeStream<messages::FooInit>(server_loop, MakeStream(server_loop, setup.server_fd), *init);
        server_loop.loop();
    });

    auto init = ConnectStream<messages::FooInit>(*setup.loop, MakeStream(*setup.loop, setup.client_fd));

    init.reset();
    server_thread.join();
    KJ_EXPECT(true);
}

KJ_TEST("ConnectStream throws when the socket disconnects after receiving data")
{
    TestSetup setup;

    std::thread server_thread([&setup]() {
        char buf[128];

        ssize_t bytes_received =
            recv(setup.server_fd, buf, sizeof(buf), 0);

        if (bytes_received > 0) {
            close(setup.server_fd);
        }
    });

    try {
        auto init = ConnectStream<messages::FooInit>(*setup.loop, MakeStream(*setup.loop, setup.client_fd));

        if (server_thread.joinable()) server_thread.join();
        KJ_EXPECT(false);
    } catch (const std::runtime_error& e) {
        if (server_thread.joinable()) server_thread.join();

        std::string_view reason = e.what();
        KJ_EXPECT(reason == "IPC client method called after disconnect.");
    }
}

KJ_TEST("ConnectStream throws when a connection accepted from a listener disconnects after receiving data")
{
    UnixListener listener;

    TestSetup setup([&listener](int fds[2]) {
        fds[0] = listener.MakeConnectedSocket(); // client_fd
        fds[1] = listener.release();             // server_fd
    });

    std::thread server_thread([&setup]() {
        char buf[128];

        int connection_fd = accept(setup.server_fd, nullptr, nullptr);

        if (connection_fd >= 0) {
            ssize_t bytes_received =
                recv(connection_fd, buf, sizeof(buf), 0);

            if (bytes_received > 0) {
                close(connection_fd);
            }
        }
        close(setup.server_fd);
    });

    try {
        auto init = ConnectStream<messages::FooInit>(*setup.loop, MakeStream(*setup.loop, setup.client_fd));

        if (server_thread.joinable()) server_thread.join();
        KJ_EXPECT(false);
    } catch (const std::runtime_error& e) {
        if (server_thread.joinable()) server_thread.join();

        std::string_view reason = e.what();
        KJ_EXPECT(reason == "IPC client method called after disconnect.");
    }
}

} // namespace
} // namespace test
} // namespace mp
