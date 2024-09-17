#include <client.cpp>
#include <server.cpp>

#include <opendht/crypto.h>
#include <opendht/thread_pool.h>

#include <string>
#include <chrono>
using namespace std::chrono_literals;

#if __has_include(<fmt/std.h>)
#include <fmt/std.h>
#else
#include <fmt/ostream.h>
#endif

int
main()
{
    // Set the log level to 0 to avoids pj logs
    pj_log_set_level(0);

    // This is the root certificate that will be used to sign other certificates
    // In this example, we use the same CA to sign the server and client certificates
    auto ca = dht::crypto::generateIdentity("ca");
    auto id_server = dht::crypto::generateIdentity("server", ca);
    auto id_client = dht::crypto::generateIdentity("client", ca);

    dht::ThreadPool::io().run([id_server] { dhtnet::server(id_server); });

    dhtnet::client(id_client, id_server);

    // Wait for the threads to complete
    dht::ThreadPool::io().join();
    return 0;
}