#include <server/server.cpp>

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
    auto ca = dht::crypto::generateIdentity("ca");

    auto id_server = dht::crypto::generateIdentity("server", ca);

    dhtnet::server(id_server);


    return 0;
}