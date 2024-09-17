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

int main() {
    // This is the root certificate that will be used to sign other certificates
    // In this example, we use the same CA to sign the server and client certificates
    auto ca = dht::crypto::generateIdentity("ca");

    // Shared pointer to hold the server identity
    auto id_server = std::make_shared<dht::crypto::Identity>();

    // Run the server in a separate thread
    dht::ThreadPool::io().run([ca, id_server] {
        try {
            *id_server = dhtnet::server(ca);
        } catch (const std::exception& e) {
            std::cerr << "Server error: " << e.what() << std::endl;
        }
    });

    // Run the client in a separate thread
    dht::ThreadPool::io().run([ca, id_server] {
        try {
            // Wait until the server identity is initialized
            while (!id_server->first || !id_server->second) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            auto id_client = dhtnet::client(*id_server, ca);
        } catch (const std::exception& e) {
            std::cerr << "Client error: " << e.what() << std::endl;
        }
    });

    // Wait for the threads to complete
    dht::ThreadPool::io().join();

    return 0;
}