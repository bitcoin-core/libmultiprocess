// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mp/test/foo.capnp.h>
#include <mp/test/foo.capnp.proxy.h>

#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <future>
#include <functional>
#include <kj/async.h>
#include <kj/common.h>
#include <kj/debug.h>
#include <kj/memory.h>
#include <kj/test.h>
#include <memory>
#include <mp/proxy-io.h>
#include <mutex>
#include <ratio> // IWYU pragma: keep
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

namespace mp {
namespace test {
namespace {

class UnixListener
{
public:
    UnixListener()
    {
        char dir_template[] = "/tmp/mptest-listener-XXXXXX";
        char* dir = mkdtemp(dir_template);
        KJ_REQUIRE(dir != nullptr);
        m_dir = dir;
        m_path = m_dir + "/socket";

        m_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        KJ_REQUIRE(m_fd >= 0);

        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        KJ_REQUIRE(m_path.size() < sizeof(addr.sun_path));
        std::strncpy(addr.sun_path, m_path.c_str(), sizeof(addr.sun_path) - 1);
        KJ_REQUIRE(bind(m_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
        KJ_REQUIRE(listen(m_fd, SOMAXCONN) == 0);
    }

    ~UnixListener()
    {
        if (m_fd >= 0) close(m_fd);
        if (!m_path.empty()) unlink(m_path.c_str());
        if (!m_dir.empty()) rmdir(m_dir.c_str());
    }

    int release()
    {
        int fd = m_fd;
        m_fd = -1;
        return fd;
    }

    int Connect() const
    {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        KJ_REQUIRE(fd >= 0);

        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        KJ_REQUIRE(m_path.size() < sizeof(addr.sun_path));
        std::strncpy(addr.sun_path, m_path.c_str(), sizeof(addr.sun_path) - 1);
        KJ_REQUIRE(connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
        return fd;
    }

private:
    int m_fd{-1};
    std::string m_dir;
    std::string m_path;
};

class ClientSetup
{
public:
    explicit ClientSetup(int fd)
        : thread([this, fd] {
              EventLoop loop("mptest-client", [](mp::LogMessage log) {
                  KJ_LOG(INFO, log.level, log.message);
                  if (log.level == mp::Log::Raise) throw std::runtime_error(log.message);
              });
              client_promise.set_value(ConnectStream<messages::FooInterface>(loop, fd));
              loop.loop();
          })
    {
        client = client_promise.get_future().get();
    }

    ~ClientSetup()
    {
        client.reset();
        thread.join();
    }

    std::promise<std::unique_ptr<ProxyClient<messages::FooInterface>>> client_promise;
    std::unique_ptr<ProxyClient<messages::FooInterface>> client;

    //! Thread variable should be after other struct members so the thread does
    //! not start until the other members are initialized.
    std::thread thread;
};

class ListenSetup
{
public:
    ListenSetup()
        : thread([this] {
              EventLoop loop("mptest-server", [this](mp::LogMessage log) {
                  KJ_LOG(INFO, log.level, log.message);
                  if (log.level == mp::Log::Raise) throw std::runtime_error(log.message);
              });
              loop.testing_hook_connected = [&] {
                  std::lock_guard<std::mutex> lock(counter_mutex);
                  ++connected_count;
                  counter_cv.notify_all();
              };
              FooImplementation foo;
              ListenConnections<messages::FooInterface>(loop, listener.release(), foo);
              ready_promise.set_value();
              loop.loop();
          })
    {
        ready_promise.get_future().get();
    }

    ~ListenSetup()
    {
        thread.join();
    }

    void WaitForConnectedCount(size_t expected_count)
    {
        std::unique_lock<std::mutex> lock(counter_mutex);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        const bool matched = counter_cv.wait_until(lock, deadline, [&] {
            return connected_count >= expected_count;
        });
        KJ_REQUIRE(matched);
    }

    UnixListener listener;
    std::promise<void> ready_promise;
    std::mutex counter_mutex;
    std::condition_variable counter_cv;
    size_t connected_count{0};
    //! Thread variable should be after other struct members so the thread does
    //! not start until the other members are initialized.
    std::thread thread;
    
};

KJ_TEST("ListenConnections accepts incoming connections")
{
    ListenSetup setup;
    auto client = std::make_unique<ClientSetup>(setup.listener.Connect());

    setup.WaitForConnectedCount(1);
    KJ_EXPECT(client->client->add(1, 2) == 3);
}

} // namespace
} // namespace test
} // namespace mp
