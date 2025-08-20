#include "upnp/upnp_control.h"
#include "upnp/upnp_context.h"
#include "string_utils.h"
#include <asio/executor_work_guard.hpp>
#include <opendht/log.h>

#include <readline/readline.h>
#include <readline/history.h>

namespace {

void
print_help()
{
    fmt::print("Commands:\n"
                    "  help, h, ?\n"
                    "  quit, exit, q, x\n"
                    "  ip\n"
                    "  open <port> <protocol>\n"
                    "  close <port>\n"
                    "  mappings\n");
}

void
print_mappings(const std::shared_ptr<dhtnet::upnp::UPnPContext>& upnpContext)
{
    for (auto const& igdInfo : upnpContext->getIgdsInfo()) {
        fmt::print("\nIGD: \"{}\" [local IP: {} - public IP: {}]\n",
                   igdInfo.uid,
                   igdInfo.localIp.toString(),
                   igdInfo.publicIp.toString());

        if (igdInfo.mappingInfoList.empty())
            continue;

        static const char *format = "{:>8} {:>12} {:>12} {:>8} {:>8} {:>16} {:>16}  {}\n";
        fmt::print(format, "Protocol", "ExternalPort", "InternalPort", "Duration",
                   "Enabled?", "InternalClient", "RemoteHost", "Description");
        for (auto const& mappingInfo : igdInfo.mappingInfoList) {
            fmt::print(format,
                       mappingInfo.protocol,
                       mappingInfo.externalPort,
                       mappingInfo.internalPort,
                       mappingInfo.leaseDuration,
                       mappingInfo.enabled,
                       mappingInfo.internalClient,
                       mappingInfo.remoteHost.empty() ? "any" : mappingInfo.remoteHost,
                       mappingInfo.description);
        }
    }
}

std::string to_lower(std::string_view str_v) {
    std::string str(str_v);
    std::transform(str.begin(), str.end(), str.begin(),
                   [](unsigned char c){ return std::tolower(c); }
                  );
    return str;
}

} // namespace

int
main(int argc, char** argv)
{
    auto ioContext  = std::make_shared<asio::io_context>();
    std::shared_ptr<dht::log::Logger> logger = dht::log::getStdLogger();
    auto upnpContext = std::make_shared<dhtnet::upnp::UPnPContext>(ioContext, logger);
    upnpContext->setAvailableMappingsLimits(dhtnet::upnp::PortType::TCP, 0, 0);
    upnpContext->setAvailableMappingsLimits(dhtnet::upnp::PortType::UDP, 0, 0);

    auto ioContextRunner = std::make_shared<std::thread>([context = ioContext, logger]() {
        try {
            auto work = asio::make_work_guard(*context);
            context->run();
        } catch (const std::exception& ex) {
            logger->error("Unexpected io_context thread exception: {}", ex.what());
        }
    });

    auto controller = std::make_shared<dhtnet::upnp::Controller>(upnpContext);
    std::set<std::shared_ptr<dhtnet::upnp::Mapping>> mappings;

    while (true) {
        char* l = readline("> ");
        if (not l)
            break;
        std::string_view line{l};
        if (line.empty())
            continue;
        add_history(l);
        auto args = dhtnet::split_string(line, ' ');
        auto command = args[0];
        if (command == "quit" || command == "exit" || command == "q" || command == "x")
            break;
        if (command == "help" || command == "h" || command == "?") {
            print_help();
        }
        else if (command == "ip") {
            fmt::print("{}\n", controller->getExternalIP().toString());
        } else if (command == "open") {
            if (args.size() < 3) {
                fmt::print("Usage: open <port> <protocol>\n");
                continue;
            }
            auto protocol = to_lower(args[2]) == "udp" ? dhtnet::upnp::PortType::UDP : dhtnet::upnp::PortType::TCP;
            mappings.emplace(controller->reserveMapping(dhtnet::to_int<in_port_t>(args[1]), protocol));
        } else if (command == "close") {
            if (args.size() < 2) {
                fmt::print("Usage: close <port>\n");
                continue;
            }
            auto port = dhtnet::to_int<in_port_t>(args[1]);
            for (auto it = mappings.begin(); it != mappings.end(); ) {
                if ((*it)->getExternalPort() == port) {
                    controller->releaseMapping(**it);
                    it = mappings.erase(it);
                } else {
                    ++it;
                }
            }
        } else if (command == "mappings") {
            print_mappings(upnpContext);
        } else if (command == "restart") {
            upnpContext->restart();
        } else {
            fmt::print("Unknown command: {}\n", command);
        }
    }
    fmt::print("Stopping...\n");
    for (const auto& c: mappings)
        controller->releaseMapping(*c);
    mappings.clear();

    ioContext->stop();
    ioContextRunner->join();
}
