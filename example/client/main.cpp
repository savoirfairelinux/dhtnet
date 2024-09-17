#include <client/client.cpp>

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
main(int argc, char** argv)
{
    // Set the log level to 0 to avoids pj logs
    pj_log_set_level(0);

    // This is the root certificate that will be used to sign other certificates
    auto ca = dht::crypto::generateIdentity("ca_client");

    auto id_client = dht::crypto::generateIdentity("client", ca);

    auto id_server = dht::InfoHash(argv[1]);

    dhtnet::client(id_client, id_server);

    // Wait for the threads to complete
    dht::ThreadPool::io().join();
    return 0;
}