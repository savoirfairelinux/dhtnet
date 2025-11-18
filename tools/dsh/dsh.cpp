/*
 *  Copyright (C) 2004-2025 Savoir-faire Linux Inc.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include "dsh.h"
#include "../common.h"
#include <opendht/log.h>
#include <opendht/crypto.h>

#include <asio/io_context.hpp>
#include <sys/types.h>
#include <sys/wait.h>

namespace dhtnet {

const int READ_END = 0;
const int WRITE_END = 1;

void
create_pipe(int apipe[2])
{
#ifdef __APPLE__
    if (pipe(apipe) < 0)
        perror("pipe");

    if (fcntl(apipe[0], F_SETFD, FD_CLOEXEC) < 0)
        perror("unable to set pipe FD_CLOEXEC");

    if (fcntl(apipe[1], F_SETFD, FD_CLOEXEC) < 0)
        perror("unable to set pipe FD_CLOEXEC");
#else
    if (pipe2(apipe, O_CLOEXEC) == -1) {
        perror("pipe2");
        exit(EXIT_FAILURE);
    }
#endif
}

void
child_proc(const int in_pipe[2], const int out_pipe[2], const int error_pipe[2], const std::string& name)
{
    // close unused write end of input pipe and read end of output pipe
    close(in_pipe[WRITE_END]);
    close(out_pipe[READ_END]);
    close(error_pipe[READ_END]);

    // replace stdin with input pipe
    if (dup2(in_pipe[READ_END], STDIN_FILENO) == -1) {
        perror("dup2: error replacing stdin");
        exit(EXIT_FAILURE);
    }

    // replace stdout with output pipe
    if (dup2(out_pipe[WRITE_END], STDOUT_FILENO) == -1) {
        perror("dup2: error replacing stdout");
        exit(EXIT_FAILURE);
    }
    // replace stderr with error pipe
    if (dup2(error_pipe[WRITE_END], STDERR_FILENO) == -1) {
        perror("dup2: error replacing stderr");
        exit(EXIT_FAILURE);
    }

    // prepare arguments
    const char* args[] = {name.c_str(), NULL};
    // execute subprocess
    execvp(args[0], const_cast<char* const*>(args));

    // if execv returns, an error occurred
    perror("execvp");
    exit(EXIT_FAILURE);
}

dhtnet::Dsh::Dsh(dht::crypto::Identity identity,
                 const std::string& bootstrap,
                 const std::string& turn_host,
                 const std::string& turn_user,
                 const std::string& turn_pass,
                 const std::string& turn_realm,
                 bool anonymous)
    : logger(dht::log::getStdLogger())
    , certStore(std::make_shared<tls::CertificateStore>(cachePath() / "certstore", logger))
    , iceFactory(std::make_shared<IceTransportFactory>(logger))
    , ioContext(std::make_shared<asio::io_context>())
    , trustStore(std::make_shared<tls::TrustStore>(*certStore))
{
    auto ca = identity.second->issuer;
    trustStore->setCertificateStatus(ca->getId().toString(), tls::TrustStore::PermissionStatus::ALLOWED);
    // Build a server
    auto config = connectionManagerConfig(
        identity, bootstrap, logger, certStore, ioContext, iceFactory, turn_host, turn_user, turn_pass, turn_realm);
    // create a connection manager
    connectionManager = std::make_unique<ConnectionManager>(std::move(config));

    connectionManager->dhtStarted();
    connectionManager->onICERequest([this, identity, anonymous](const DeviceId& deviceId) { // handle ICE request
        return trustStore->isAllowed(*certStore->getCertificate(deviceId.toString()), anonymous);
    });

    std::mutex mtx;
    std::unique_lock lk {mtx};

    connectionManager->onChannelRequest([&](const std::shared_ptr<dht::crypto::Certificate>&, const std::string& name) {
        // handle channel request
        if (logger)
            logger->debug("Channel request received");
        return true;
    });

    connectionManager->onConnectionReady(
        [&](const DeviceId&, const std::string& name, std::shared_ptr<ChannelSocket> socket) {
            // handle connection ready
            try {
                // Create a pipe for communication with the  subprocess
                // create pipes
                int in_pipe[2], out_pipe[2], error_pipe[2];
                create_pipe(in_pipe);
                create_pipe(out_pipe);
                create_pipe(error_pipe);

                ioContext->notify_fork(asio::io_context::fork_prepare);

                // Fork to create a child process
                pid_t pid = fork();
                if (pid == -1) {
                    perror("fork");
                    return EXIT_FAILURE;
                } else if (pid == 0) { // Child process
                    ioContext->notify_fork(asio::io_context::fork_child);
                    child_proc(in_pipe, out_pipe, error_pipe, name);
                    return EXIT_SUCCESS; // never reached
                } else {
                    ioContext->notify_fork(asio::io_context::fork_parent);

                    // close unused read end of input pipe and write end of output pipe
                    close(in_pipe[READ_END]);
                    close(out_pipe[WRITE_END]);
                    close(error_pipe[WRITE_END]);

                    asio::io_context& ioContextRef = *ioContext;
                    // create stream descriptors
                    auto inStream = std::make_shared<asio::posix::stream_descriptor>(ioContextRef.get_executor(),
                                                                                     in_pipe[WRITE_END]);
                    auto outStream = std::make_shared<asio::posix::stream_descriptor>(ioContextRef.get_executor(),
                                                                                      out_pipe[READ_END]);
                    auto errorStream = std::make_shared<asio::posix::stream_descriptor>(ioContextRef.get_executor(),
                                                                                        error_pipe[READ_END]);

                    if (socket) {
                        socket->setOnRecv([this, socket, inStream](const uint8_t* data, size_t size) {
                            auto data_copy = std::make_shared<std::vector<uint8_t>>(data, data + size);
                            // write on pipe to sub child
                            std::error_code ec;
                            asio::async_write(*inStream,
                                              asio::buffer(*data_copy),
                                              [data_copy, this](const std::error_code& error, std::size_t bytesWritten) {
                                                  if (error) {
                                                      if (logger)
                                                          logger->error("Write error: {}", error.message());
                                                  }
                                              });
                            return size;
                        });

                        // read from pipe to sub child

                        // Create a buffer to read data into
                        auto buffer = std::make_shared<std::vector<uint8_t>>(BUFFER_SIZE);

                        // Create a shared_ptr to the stream_descriptor
                        readFromPipe(socket, outStream, buffer);
                        readFromPipe(socket, errorStream, buffer);

                        return EXIT_SUCCESS;
                    }
                }

            } catch (const std::exception& e) {
                if (logger)
                    logger->error("Error: {}", e.what());
            }
            return 0;
        });
}

dhtnet::Dsh::Dsh(dht::crypto::Identity identity,
                 const std::string& bootstrap,
                 dht::PkId peer_id,
                 const std::string& binary,
                 const std::string& turn_host,
                 const std::string& turn_user,
                 const std::string& turn_pass,
                 const std::string& turn_realm)
    : Dsh(identity, bootstrap, turn_host, turn_user, turn_pass, turn_realm, false)
{
    // Build a client
    std::condition_variable cv;
    connectionManager->connectDevice(peer_id, binary, [&](std::shared_ptr<ChannelSocket> socket, const dht::PkId&) {
        if (socket) {
            socket->setOnRecv([socket](const uint8_t* data, size_t size) {
                std::cout.write((const char*) data, size);
                std::cout.flush();
                return size;
            });
            // Create a buffer to read data into
            auto buffer = std::make_shared<std::vector<uint8_t>>(BUFFER_SIZE);

            // Create a shared_ptr to the stream_descriptor
            auto stdinPipe = std::make_shared<asio::posix::stream_descriptor>(*ioContext, ::dup(STDIN_FILENO));
            readFromPipe(socket, stdinPipe, buffer);

            socket->onShutdown([this](const std::error_code& ec) {
                if (logger)
                    logger->debug("Exit program {}", ec.message());
                ioContext->stop();
            });
        }
    });

    connectionManager->onConnectionReady(
        [&](const DeviceId&, const std::string& name, std::shared_ptr<ChannelSocket> socket_received) {
            if (logger)
                logger->debug("Connected!");
        });
}

void
dhtnet::Dsh::run()
{
    auto work = asio::make_work_guard(*ioContext);
    ioContext->run();
}

dhtnet::Dsh::~Dsh()
{
    ioContext->stop();
}

} // namespace dhtnet