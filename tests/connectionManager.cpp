/*
 *  Copyright (C) 2017-2023 Savoir-faire Linux Inc.
 *  Author: Sébastien Blin <sebastien.blin@savoirfairelinux.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include <iostream>
#include <filesystem>


#include <cppunit/TestAssert.h>
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>

#include <condition_variable>

#include "connectionmanager.h"
#include "multiplexed_socket.h"
#include "test_runner.h"
#include "certstore.h"

using namespace std::literals::chrono_literals;

namespace jami {
namespace test {

class ConnectionManagerTest : public CppUnit::TestFixture
{
public:
    ConnectionManagerTest() {}
    ~ConnectionManagerTest() { }
    static std::string name() { return "ConnectionManager"; }
    void setUp();
    void tearDown();

    std::string aliceId;
    std::string bobId;


//Create a lock to be used in the test units
    std::mutex mtx;
    std::unique_lock<std::mutex> lock {mtx};
    std::shared_ptr<asio::io_context> ioContext;
    std::thread ioContextRunner;
    std::shared_ptr<Logger> logger;
private:
     void testConnectDevice();
    // void testAcceptConnection();
    // void testMultipleChannels();
    // void testMultipleChannelsOneDeclined();
    // void testMultipleChannelsSameName();
    // void testDeclineConnection();
    // void testSendReceiveData();
    // void testAcceptsICERequest();
    // void testDeclineICERequest();
    // void testChannelRcvShutdown();
    // void testChannelSenderShutdown();
    // void testCloseConnectionWith();
    // void testShutdownCallbacks();
    // void testFloodSocket();
    // void testDestroyWhileSending();
    // void testIsConnecting();
    // void testCanSendBeacon();
    // void testCannotSendBeacon();
    // void testConnectivityChangeTriggerBeacon();
    // void testOnNoBeaconTriggersShutdown();
    // void testShutdownWhileNegotiating();

    CPPUNIT_TEST_SUITE(ConnectionManagerTest);

    // CPPUNIT_TEST(testAcceptsICERequest);
    // CPPUNIT_TEST(testDeclineICERequest);

     CPPUNIT_TEST(testConnectDevice);

    // CPPUNIT_TEST(testIsConnecting);

    // CPPUNIT_TEST(testAcceptConnection);
    // CPPUNIT_TEST(testDeclineConnection);

    // CPPUNIT_TEST(testMultipleChannels);
    // CPPUNIT_TEST(testMultipleChannelsOneDeclined);
    // CPPUNIT_TEST(testMultipleChannelsSameName);
    
    // CPPUNIT_TEST(testSendReceiveData);

    // CPPUNIT_TEST(testChannelRcvShutdown);
    // CPPUNIT_TEST(testChannelSenderShutdown);

    // CPPUNIT_TEST(testCloseConnectionWith);
    // CPPUNIT_TEST(testShutdownCallbacks);
    // CPPUNIT_TEST(testFloodSocket);
    // CPPUNIT_TEST(testDestroyWhileSending);

    // CPPUNIT_TEST(testCanSendBeacon);
    // CPPUNIT_TEST(testCannotSendBeacon);
    // CPPUNIT_TEST(testConnectivityChangeTriggerBeacon);
    // CPPUNIT_TEST(testOnNoBeaconTriggersShutdown);
    // CPPUNIT_TEST(testShutdownWhileNegotiating);
    CPPUNIT_TEST_SUITE_END();
};

CPPUNIT_TEST_SUITE_NAMED_REGISTRATION(ConnectionManagerTest, ConnectionManagerTest::name());





void
ConnectionManagerTest::setUp()
{
    logger = std::shared_ptr<Logger>();
    ioContext = std::make_shared<asio::io_context>();
    ioContextRunner = std::thread([context = ioContext]() {
        try {
            auto work = asio::make_work_guard(*context);
            context->run();
        } catch (const std::exception& ex) {
            //print the error;
        }
    });

//DHT node creation: To make a connection manager at first a DHT node should be created
    std::string name = "Alice";
    auto aliceId = dht::crypto::generateIdentity(name);
    auto alicCertStore = std::make_unique<tls::CertificateStore>(name, logger);

    dht::DhtRunner::Config dhtConfig;
    dhtConfig.dht_config.id = aliceId;
    dhtConfig.threaded = true;
 
    dht::DhtRunner::Context dhtContext;
    dhtContext.certificateStore = [&](const dht::InfoHash& pk_id) {
        std::vector<std::shared_ptr<dht::crypto::Certificate>> ret;
        if (auto cert = alicCertStore->getCertificate(pk_id.toString()))
            ret.emplace_back(std::move(cert));
        return ret;
    };

    auto runner = std::make_shared<dht::DhtRunner>();
    runner->run(dhtConfig, std::move(dhtContext));
//DHT node creation end:


//ConnectionManager creation:
    auto config = std::make_shared<ConnectionManager::Config>();
    config->dht = runner;
    config->id = aliceId;
   
    config->ioContext = ioContext;
 
    std::filesystem::path currentPath = std::filesystem::current_path();
    std::filesystem::path tempDirPath = currentPath / "test_temp_dir";

    config->cachePath = tempDirPath.string();


    auto alicConMngr = std::make_unique<ConnectionManager>(config);
//ConnectionManager creation end:


/*
*/

////////////////////////////// the same as above but for Bob//////////////////////////////
/*
//DHT node creation: To make a connection manager at first a DHT node should be created
    std::string name = "Bob";

    dht::DhtRunner::Config dhtConfig;

    auto bobId = dht::crypto::generateIdentity(name);
    
    dhtConfig.dht_config.id = bobId;
    dhtConfig.threaded = true;

    auto ioContext = std::make_shared<asio::io_context>();
    auto ioContextRunner = std::thread([context = ioContext]() {
        try {
            auto work = asio::make_work_guard(*context);
            context->run();
        } catch (const std::exception& ex) {
            //print the error;
        }
    });

    auto alicCertStore = std::make_unique<tls::CertificateStore>(name);
 
    dht::DhtRunner::Context dhtContext;
    dhtContext.certificateStore = [&](const dht::InfoHash& pk_id) {
        std::vector<std::shared_ptr<dht::crypto::Certificate>> ret;
        if (auto cert = alicCertStore->getCertificate(pk_id.toString()))
            ret.emplace_back(std::move(cert));
        return ret;
    };

    auto runner = std::make_shared<dht::DhtRunner>();
    runner->run(dhtConfig, std::move(dhtContext));
//DHT node creation end:


//ConnectionManager creation:
    auto config = std::make_shared<ConnectionManager::Config>();
    config->dht = runner;
    config->id = aliceId;
    config->ioContext = ioContext;

    std::filesystem::path currentPath = std::filesystem::current_path();
    std::filesystem::path tempDirPath = currentPath / "temp";

    config->cachePath = tempDirPath.string();

    auto alicConMngr = std::make_unique<ConnectionManager>(config);
//ConnectionManager creation end:



  
    
  
//make an ICE connection: the call back function return true to make sure the request is accepted.
    alicConMngr->onICERequest([](const DeviceId&) { 
        return true;
    });

//make an ICE connection: the call back function return true to make sure the request is accepted.
    alicConMngr->onICERequest([](const DeviceId&) { 
        return true;
    });


    auto bobDevicId = bobId.second->getLongId();
    auto bobUri = bobId.second->getIssuerUID(); 

*/



}

/*
    auto identifier = bobId.first->getPublicKey().getLongId();
    auto identifier = bobId.second->getLongId();
    auto identifier = bobId.second->getPublicKey().getLongId(); 
*/


void
ConnectionManagerTest::tearDown()
{
    //wait_for_removal_of({aliceId, bobId});  //?????????????????????????????????
    ioContext->stop();
    if (ioContextRunner.joinable())
        ioContextRunner.join();
}


void
ConnectionManagerTest::testConnectDevice()
{

    CPPUNIT_ASSERT_EQUAL(2,2);
    
    /*
    auto aliceAccount = Manager::instance().getAccount<JamiAccount>(aliceId);
    auto bobAccount = Manager::instance().getAccount<JamiAccount>(bobId);

    auto bobDeviceId = DeviceId(std::string(bobAccount->currentDeviceId()));

    bobAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });
    aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
    std::condition_variable cv, cvReceive;
    bool successfullyConnected = false;
    bool successfullyReceive = false;

    bobAccount->connectionManager().onChannelRequest(
        [&successfullyReceive, &cvReceive](const std::shared_ptr<dht::crypto::Certificate>&,
                                           const std::string& name) {
            successfullyReceive = name == "git://*";
            cvReceive.notify_one();
            return true;
        });

    aliceAccount->connectionManager().connectDevice(bobDeviceId,
                                                    "git://*",
                                                    [&](std::shared_ptr<ChannelSocket> socket,
                                                        const DeviceId&) {
                                                        if (socket) {
                                                            successfullyConnected = true;
                                                        }
                                                        cv.notify_one();
                                                    });

    CPPUNIT_ASSERT(cvReceive.wait_for(lk, 60s, [&] { return successfullyReceive; }));
    CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] { return successfullyConnected; }));

    */
}



// void
// ConnectionManagerTest::testConnectDevice()
// {
// //Scenario: Alice's device wants connect to Bob's device. 


// //Step 0: Make a connection manager for Alice and Bob devices (Done in setUp()).
// //step 1: make an ICE connection (Done in setUp()).


// //Step 2: To triger callback on incoming request
//     std::condition_variable bobConVar;
//     bool isBobRecvChanlReq = false; //A variable to specify: "If the Bob's device received channel request?".

//     auto chanlReqCalBack =  [&isBobRecvChanlReq, &bobConVar]
//                             (const std::shared_ptr<dht::crypto::Certificate>&, const std::string& name) 
//                             {
//                                 isBobRecvChanlReq = name == "dumyName";
//                                 bobConVar.notify_one();
//                                 return true;
//                             };

//     bobConMngr.onChannelRequest(chanlReqCalBack);


// //Step 3: Create a TlS socket with Bob's device.
//     std::condition_variable alicConVar;
//     bool isAlicConnected = false; //A variable to specify: "If the Alice's device connected to the Bob's device?".

//     auto conctDevicCalBack =    [&]
//                                 (std::shared_ptr<ChannelSocket> socket, const DeviceId&) 
//                                 {
//                                     if (socket) { isAlicConnected = true; }
//                                     alicConVar.notify_one();
//                                 };

//     alicConMngr.connectDevice(bobDevicId, "dumyName", conctDevicCalBack);


// //Step 4: to check if Alice connected to Bob?
//     CPPUNIT_ASSERT(alicConVar.wait_for(lock, 60s, [&] { return isAlicConnected; }));
// }



// /*
// void
// ConnectionManagerTest::testAcceptConnection()
// {
//     auto aliceAccount = Manager::instance().getAccount<JamiAccount>(aliceId);
//     auto bobAccount = Manager::instance().getAccount<JamiAccount>(bobId);
//     auto bobDeviceId = DeviceId(std::string(bobAccount->currentDeviceId()));

//     bobAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });
//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });

//     std::mutex mtx;
//     std::unique_lock<std::mutex> lk {mtx};
//     std::condition_variable cv;
//     bool successfullyConnected = false;
//     bool successfullyReceive = false;
//     bool receiverConnected = false;

//     bobAccount->connectionManager().onChannelRequest(
//         [&successfullyReceive](const std::shared_ptr<dht::crypto::Certificate>&,
//                                const std::string& name) {
//             successfullyReceive = name == "git://*";
//             return true;
//         });

//     bobAccount->connectionManager().onConnectionReady(
//         [&receiverConnected](const DeviceId&,
//                              const std::string& name,
//                              std::shared_ptr<ChannelSocket> socket) {
//             receiverConnected = socket && (name == "git://*");
//         });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "git://*",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });

//     CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] {
//         return successfullyReceive && successfullyConnected && receiverConnected;
//     }));
// }
// */
// void
// ConnectionManagerTest::testAcceptConnection()
// {

//     std::condition_variable cv;
//     bool successfullyConnected = false;
//     bool successfullyReceive = false;

//     auto chanlReqCalBack =  [&successfullyReceive]
//                             (const std::shared_ptr<dht::crypto::Certificate>&, const std::string& name) 
//                             { 
//                                 successfullyReceive = name == "dumyname";
//                                 return true;
//                             };

//     bobConMngr.onChannelRequest(chanlReqCalBack);



//     bool receiverConnected = false;

//     auto conctReadyCalBack =[&receiverConnected]
//                             (const DeviceId& deviceId, const std::string& name, std::shared_ptr<ChannelSocket> socket) 
//                             {
//                                 receiverConnected = socket && (name == "dumyname");
//                             };
        
//     bobConMngr.onConnectionReady(conctReadyCalBack);


//     auto conctDevicCalBack =[&]
//                             (std::shared_ptr<ChannelSocket> socket, const DeviceId&) 
//                             {
//                                 if (socket) 
//                                     successfullyConnected = true;
//                                 cv.notify_one();
//                             };

//     alicConMngr.connectDevice(bobDevicId, "dumyname", conctDevicCalBack);



//     CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] {
//         return successfullyReceive && successfullyConnected && receiverConnected;
//     }));

// }

// /* 
// void
// ConnectionManagerTest::testDeclineConnection()
// {
//     auto aliceAccount = Manager::instance().getAccount<JamiAccount>(aliceId);
//     auto bobAccount = Manager::instance().getAccount<JamiAccount>(bobId);
//     auto bobDeviceId = DeviceId(std::string(bobAccount->currentDeviceId()));

//     bobAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });
//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });

//     std::mutex mtx;
//     std::unique_lock<std::mutex> lk {mtx};
//     std::condition_variable cv;
//     bool successfullyConnected = false;
//     bool successfullyReceive = false;
//     bool receiverConnected = false;

//     bobAccount->connectionManager().onChannelRequest(
//         [&successfullyReceive](const std::shared_ptr<dht::crypto::Certificate>&,
//                                const std::string&) {
//             successfullyReceive = true;
//             return false;
//         });

//     bobAccount->connectionManager().onConnectionReady(
//         [&receiverConnected](const DeviceId&,
//                              const std::string&,
//                              std::shared_ptr<ChannelSocket> socket) {
//             if (socket)
//                 receiverConnected = true;
//         });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "git://*",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });
//     cv.wait_for(lk, 30s);
//     CPPUNIT_ASSERT(successfullyReceive);
//     CPPUNIT_ASSERT(!successfullyConnected);
//     CPPUNIT_ASSERT(!receiverConnected);
// }
//  */
// void
// ConnectionManagerTest::testDeclineConnection()
// {

//     std::condition_variable cv;
//     bool successfullyConnected = false;
//     bool successfullyReceive = false;
//     bool receiverConnected = false;


//     auto chanlReqCalBack =  [&successfullyReceive]
//                             (const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) 
//                             {
//                                 successfullyReceive = true;
//                                 return false;  //this is the point??????????????????????????????????????????????????????
//                             };

//     bobConMngr.onChannelRequest(chanlReqCalBack);


//     auto conctReadyCalBack =[&receiverConnected]
//                             (const DeviceId&, const std::string&, std::shared_ptr<ChannelSocket> socket) 
//                             {
//                             if (socket)
//                                 receiverConnected = true;
//                             };

//     bobConMngr.onConnectionReady(conctReadyCalBack);


//     auto conctDevicCalBack =[&]
//                             (std::shared_ptr<ChannelSocket> socket, const DeviceId&) 
//                             {
//                                 if (socket)
//                                     successfullyConnected = true;
//                                 cv.notify_one();
//                             };   


//     alicConMngr.connectDevice(bobDevicId, "dumyname", conctDevicCalBack);


//     cv.wait_for(lk, 30s);
//     CPPUNIT_ASSERT(successfullyReceive);
//     CPPUNIT_ASSERT(!successfullyConnected);
//     CPPUNIT_ASSERT(!receiverConnected);
// }




// /*
// void
// ConnectionManagerTest::testMultipleChannels()
// {
//     auto aliceAccount = Manager::instance().getAccount<JamiAccount>(aliceId);
//     auto bobAccount = Manager::instance().getAccount<JamiAccount>(bobId);
//     auto bobDeviceId = DeviceId(std::string(bobAccount->currentDeviceId()));

//     bobAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });
//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });

//     std::mutex mtx;
//     std::unique_lock<std::mutex> lk {mtx};
//     std::condition_variable cv;
//     bool successfullyConnected = false;
//     bool successfullyConnected2 = false;
//     int receiverConnected = 0;

//     bobAccount->connectionManager().onChannelRequest(
//         [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });

//     bobAccount->connectionManager().onConnectionReady(
//         [&receiverConnected](const DeviceId&,
//                              const std::string&,
//                              std::shared_ptr<ChannelSocket> socket) {
//             if (socket)
//                 receiverConnected += 1;
//         });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "git://*",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "sip://*",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             successfullyConnected2 = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });

//     CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] {
//         return successfullyConnected && successfullyConnected2 && receiverConnected == 2;
//     }));
//     CPPUNIT_ASSERT(aliceAccount->connectionManager().activeSockets() == 1);
// }
// */
// void
// ConnectionManagerTest::testMultipleChannels()
// {
//     std::condition_variable cv;
//     bool successfullyConnected = false;
//     bool successfullyConnected2 = false;
//     int receiverConnected = 0;

//     auto chanlReqCalBack =  []
//                             (const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) 
//                             { 
//                                 return true; 
//                             };

//     bobConMngr.onChannelRequest(chanlReqCalBack);


//     auto conctReadyCalBack =[&receiverConnected]
//                             (const DeviceId&, const std::string&, std::shared_ptr<ChannelSocket> socket) 
//                             {
//                                 if (socket)
//                                 receiverConnected += 1;
//                             };

//     bobConMngr.onConnectionReady(conctReadyCalBack);


//     auto conctDevicCalBack =[&]
//                             (std::shared_ptr<ChannelSocket> socket, const DeviceId&) 
//                             {
//                                 if (socket)
//                                     successfullyConnected = true;
//                                 cv.notify_one();
//                             };

//     alicConMngr.connectDevice(bobDevicId, "git://*", conctDevicCalBack);


//     auto conctDevicCalBack =[&]
//                             (std::shared_ptr<ChannelSocket> socket, const DeviceId&) 
//                             {
//                                 if (socket)
//                                     successfullyConnected2 = true;
//                                 cv.notify_one();
//                             };

//     alicConMngr.connectDevice(bobDevicId, "sip://*", conctDevicCalBack);


//     CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] {
//         return successfullyConnected && successfullyConnected2 && receiverConnected == 2;
//     }));
//     CPPUNIT_ASSERT(alicConMngr.activeSockets() == 1);
// }

// /*void
// ConnectionManagerTest::testMultipleChannelsOneDeclined()
// {
//    auto aliceAccount = Manager::instance().getAccount<JamiAccount>(aliceId);
//     auto bobAccount = Manager::instance().getAccount<JamiAccount>(bobId);
//     auto bobDeviceId = DeviceId(std::string(bobAccount->currentDeviceId()));

//     bobAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });
//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });

//     std::mutex mtx;
//     std::unique_lock<std::mutex> lk {mtx};
//     std::condition_variable cv;
//     bool successfullyNotConnected = false;
//     bool successfullyConnected2 = false;
//     int receiverConnected = 0;

//     bobAccount->connectionManager().onChannelRequest(
//         [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string& name) {
//             if (name == "git://*")
//                 return false;
//             return true;
//         });

//     bobAccount->connectionManager().onConnectionReady(
//         [&](const DeviceId&, const std::string&, std::shared_ptr<ChannelSocket> socket) {
//             if (socket)
//                 receiverConnected += 1;
//             cv.notify_one();
//         });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "git://*",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (!socket)
//                                                             successfullyNotConnected = true;
//                                                         cv.notify_one();
//                                                     });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "sip://*",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket)
//                                                             successfullyConnected2 = true;
//                                                         cv.notify_one();
//                                                     });

//     CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] {
//         return successfullyNotConnected && successfullyConnected2 && receiverConnected == 1;
//     }));
//     CPPUNIT_ASSERT(aliceAccount->connectionManager().activeSockets() == 1);
// }
// */
// void
// ConnectionManagerTest::testMultipleChannelsOneDeclined()
// {
    
//     std::condition_variable cv;
//     bool successfullyNotConnected = false;
//     bool successfullyConnected2 = false;
//     int receiverConnected = 0;


//     auto chanlReqCalBack =  []
//                             (const std::shared_ptr<dht::crypto::Certificate>&, const std::string& name) 
//                             { 
//                                 if (name == "git://*")
//                                     return false;
//                                 return true;
//                             };

//     bobConMngr.onChannelRequest(chanlReqCalBack);


//     auto conctReadyCalBack =[&receiverConnected]
//                             (const DeviceId&, const std::string&, std::shared_ptr<ChannelSocket> socket) 
//                             {
//                                 if (socket)
//                                 receiverConnected += 1;
//                             };

//     bobConMngr.onConnectionReady(conctReadyCalBack);


//     auto conctDevicCalBack =[&]
//                             (std::shared_ptr<ChannelSocket> socket, const DeviceId&) 
//                             {
//                                 if (socket)
//                                     successfullyConnected = true;
//                                 cv.notify_one();
//                             };

//     alicConMngr.connectDevice(bobDevicId, "git://*", conctDevicCalBack);


//     auto conctDevicCalBack =[&]
//                             (std::shared_ptr<ChannelSocket> socket, const DeviceId&) 
//                             {
//                                 if (socket)
//                                     successfullyConnected2 = true;
//                                 cv.notify_one();
//                             };

//     alicConMngr.connectDevice(bobDevicId, "sip://*", conctDevicCalBack);



//     CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] {
//         return successfullyNotConnected && successfullyConnected2 && receiverConnected == 1;
//     }));
//     CPPUNIT_ASSERT(aliceAccount->connectionManager().activeSockets() == 1);
// }

// /*
// void
// ConnectionManagerTest::testMultipleChannelsSameName()
// {
//     std::condition_variable cv;
//     bool successfullyConnected = false;
//     bool successfullyConnected2 = false;
//     int receiverConnected = 0;

//     bobAccount->connectionManager().onChannelRequest(
//         [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });

//     bobAccount->connectionManager().onConnectionReady(
//         [&receiverConnected](const DeviceId&,
//                              const std::string&,
//                              std::shared_ptr<ChannelSocket> socket) {
//             if (socket)
//                 receiverConnected += 1;
//         });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "git://*",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });

//     // We can open two sockets with the same name, it will be two different channel
//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "git://*",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             successfullyConnected2 = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });

//     CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] {
//         return successfullyConnected && successfullyConnected2 && receiverConnected == 2;
//     }));
// }
// */
// void
// ConnectionManagerTest::testMultipleChannelsSameName()
// {
//     std::condition_variable cv;
//     bool successfullyConnected = false;
//     bool successfullyConnected2 = false;
//     int receiverConnected = 0;



//     auto chanlReqCalBack =  []
//                             (const std::shared_ptr<dht::crypto::Certificate>&, const std::string& name) 
//                             { 
//                                 return true;
//                             };

//     bobConMngr.onChannelRequest(chanlReqCalBack);


//     auto conctReadyCalBack =[&receiverConnected]
//                             (const DeviceId&, const std::string&, std::shared_ptr<ChannelSocket> socket) 
//                             {
//                                 if (socket)
//                                 receiverConnected += 1;
//                             };

//     bobConMngr.onConnectionReady(conctReadyCalBack);


//     auto conctDevicCalBack =[&]
//                             (std::shared_ptr<ChannelSocket> socket, const DeviceId&) 
//                             {
//                                 if (socket)
//                                     successfullyConnected = true;
//                                 cv.notify_one();
//                             };

//     alicConMngr.connectDevice(bobDevicId, "git://*", conctDevicCalBack);


//     auto conctDevicCalBack =[&]
//                             (std::shared_ptr<ChannelSocket> socket, const DeviceId&) 
//                             {
//                                 if (socket)
//                                     successfullyConnected2 = true;
//                                 cv.notify_one();
//                             };

//     alicConMngr.connectDevice(bobDevicId, "sip://*", conctDevicCalBack);


//     CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] {
//         return successfullyConnected && successfullyConnected2 && receiverConnected == 2;
//     }));
// }

// //Explain this more
// /*
// void
// ConnectionManagerTest::testSendReceiveData()
// {
//     auto aliceAccount = Manager::instance().getAccount<JamiAccount>(aliceId);
//     auto bobAccount = Manager::instance().getAccount<JamiAccount>(bobId);
//     auto bobDeviceId = DeviceId(std::string(bobAccount->currentDeviceId()));

//     bobAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });
//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });

//     std::mutex mtx;
//     std::unique_lock<std::mutex> lk {mtx};
//     std::condition_variable cv;
//     std::atomic_int events(0);
//     bool successfullyConnected = false, successfullyConnected2 = false, successfullyReceive = false,
//          receiverConnected = false;
//     const uint8_t buf_other[] = {0x64, 0x65, 0x66, 0x67};
//     const uint8_t buf_test[] = {0x68, 0x69, 0x70, 0x71};
//     bool dataOk = false, dataOk2 = false;

//     bobAccount->connectionManager().onChannelRequest(
//         [&successfullyReceive](const std::shared_ptr<dht::crypto::Certificate>&,
//                                const std::string&) {
//             successfullyReceive = true;
//             return true;
//         });

//     bobAccount->connectionManager().onConnectionReady(
//         [&](const DeviceId&, const std::string& name, std::shared_ptr<ChannelSocket> socket) {
//             if (socket && (name == "test" || name == "other")) {
//                 receiverConnected = true;
//                 std::error_code ec;
//                 auto res = socket->waitForData(std::chrono::milliseconds(5000), ec);
//                 if (res == 4) {
//                     uint8_t buf[4];
//                     socket->read(&buf[0], 4, ec);
//                     if (name == "test")
//                         dataOk = std::equal(std::begin(buf), std::end(buf), std::begin(buf_test));
//                     else
//                         dataOk2 = std::equal(std::begin(buf), std::end(buf), std::begin(buf_other));
//                     events++;
//                     cv.notify_one();
//                 }
//             }
//         });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "test",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             successfullyConnected = true;
//                                                             std::error_code ec;
//                                                             socket->write(&buf_test[0], 4, ec);
//                                                         }
//                                                         events++;
//                                                         cv.notify_one();
//                                                     });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "other",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             successfullyConnected2 = true;
//                                                             std::error_code ec;
//                                                             socket->write(&buf_other[0], 4, ec);
//                                                         }
//                                                         events++;
//                                                         cv.notify_one();
//                                                     });

//     CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] {
//         return events == 4 && successfullyReceive && successfullyConnected && successfullyConnected2
//                && dataOk && dataOk2;
//     }));
// }
// */
// void
// ConnectionManagerTest::testSendReceiveData()
// {

//     std::condition_variable cv;
//     std::atomic_int events(0);
//     bool successfullyConnected = false;
//     bool successfullyConnected2 = false;
//     bool successfullyReceive = false;
//     bool receiverConnected = false;

//     const uint8_t buf_other[] = {0x64, 0x65, 0x66, 0x67};
//     const uint8_t buf_test[] = {0x68, 0x69, 0x70, 0x71};
//     bool dataOk = false;
//     bool dataOk2 = false;

    
//     auto chanlReqCalBack =  [&successfullyReceive]
//                             (const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) 
//                             {
//                                 successfullyReceive = true;
//                                 return true;
//                             }; 

//     bobConMngr.onChannelRequest(chanlReqCalBack);


//     auto conctReadyCalBack =[&]
//                             (const DeviceId&, const std::string& name, std::shared_ptr<ChannelSocket> socket) 
//                             {
//                                 if (socket && (name == "test" || name == "other")) {
//                                     receiverConnected = true;
//                                     std::error_code ec;
//                                     auto res = socket->waitForData(std::chrono::milliseconds(5000), ec);
//                                     if (res == 4) {
//                                         uint8_t buf[4];
//                                         socket->read(&buf[0], 4, ec);
//                                         if (name == "test")
//                                             dataOk = std::equal(std::begin(buf), std::end(buf), std::begin(buf_test));
//                                         else
//                                             dataOk2 = std::equal(std::begin(buf), std::end(buf), std::begin(buf_other));
//                                         events++;
//                                         cv.notify_one();
//                                     }
//                                 }
//                             };

//     bobConMngr.onConnectionReady(conctReadyCalBack);


//     auto conctDevicCalBack =[&]
//                             (std::shared_ptr<ChannelSocket> socket, const DeviceId&) 
//                             {
//                                 if (socket) {
//                                     successfullyConnected = true;
//                                     std::error_code ec;
//                                     socket->write(&buf_test[0], 4, ec);
//                                 }
//                                 events++;
//                                 cv.notify_one();
//                             };   


//     alicConMngr.connectDevice(bobDevicId, "test", conctDevicCalBack);


//     auto conctDevicCalBack2 =   [&]
//                                 (std::shared_ptr<ChannelSocket> socket, const DeviceId&) 
//                                 {
//                                     if (socket) {
//                                         successfullyConnected2 = true;
//                                         std::error_code ec;
//                                         socket->write(&buf_other[0], 4, ec);
//                                     }
//                                     events++;
//                                     cv.notify_one();
//                                 };

//     alicConMngr.connectDevice(bobDevicId, "other", conctDevicCalBack2);


//     CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] {
//         return events == 4 && successfullyReceive && successfullyConnected && successfullyConnected2
//                && dataOk && dataOk2;
//     }));
// }



// /* void
// ConnectionManagerTest::testAcceptsICERequest()
// {
//     auto aliceAccount = Manager::instance().getAccount<JamiAccount>(aliceId);
//     auto bobAccount = Manager::instance().getAccount<JamiAccount>(bobId);
//     auto bobDeviceId = DeviceId(std::string(bobAccount->currentDeviceId()));

//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });

//     std::mutex mtx;
//     std::unique_lock<std::mutex> lk {mtx};
//     std::condition_variable cv;
//     bool successfullyConnected = false;
//     bool successfullyReceive = false;
//     bool receiverConnected = false;

//     bobAccount->connectionManager().onChannelRequest(
//         [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });
//     bobAccount->connectionManager().onICERequest([&](const DeviceId&) {
//         successfullyReceive = true;
//         return true;
//     });

//     bobAccount->connectionManager().onConnectionReady(
//         [&receiverConnected](const DeviceId&,
//                              const std::string& name,
//                              std::shared_ptr<ChannelSocket> socket) {
//             receiverConnected = socket && (name == "git://*");
//         });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "git://*",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });

//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] {
//         return successfullyReceive && successfullyConnected && receiverConnected;
//     }));
// } */
// void
// ConnectionManagerTest::testAcceptsICERequest()
// {

//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });

//     std::mutex mtx;
//     std::unique_lock<std::mutex> lk {mtx};
//     std::condition_variable cv;
//     bool successfullyConnected = false;
//     bool successfullyReceive = false;
//     bool receiverConnected = false;

//     bobAccount->connectionManager().onChannelRequest(
//         [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });

//     bobAccount->connectionManager().onICERequest([&](const DeviceId&) {
//         successfullyReceive = true;
//         return true;
//     });

//     bobAccount->connectionManager().onConnectionReady(
//         [&receiverConnected](const DeviceId&,
//                              const std::string& name,
//                              std::shared_ptr<ChannelSocket> socket) {
//             receiverConnected = socket && (name == "git://*");
//         });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "git://*",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });

//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] {
//         return successfullyReceive && successfullyConnected && receiverConnected;
//     }));
// }

// /* void
// ConnectionManagerTest::testDeclineICERequest()
// {
//     auto aliceAccount = Manager::instance().getAccount<JamiAccount>(aliceId);
//     auto bobAccount = Manager::instance().getAccount<JamiAccount>(bobId);
//     auto bobDeviceId = DeviceId(std::string(bobAccount->currentDeviceId()));

//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });

//     std::mutex mtx;
//     std::unique_lock<std::mutex> lk {mtx};
//     std::condition_variable cv;
//     bool successfullyConnected = false;
//     bool successfullyReceive = false;
//     bool receiverConnected = false;

//     bobAccount->connectionManager().onChannelRequest(
//         [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });
//     bobAccount->connectionManager().onICERequest([&](const DeviceId&) {
//         successfullyReceive = true;
//         return false;
//     });

//     bobAccount->connectionManager().onConnectionReady(
//         [&receiverConnected](const DeviceId&,
//                              const std::string& name,
//                              std::shared_ptr<ChannelSocket> socket) {
//             receiverConnected = socket && (name == "git://*");
//         });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "git://*",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });

//     cv.wait_for(lk, 30s);
//     CPPUNIT_ASSERT(successfullyReceive);
//     CPPUNIT_ASSERT(!receiverConnected);
//     CPPUNIT_ASSERT(!successfullyConnected);
// } */

// //why you invoke other functions when you want to test ICErequest?
// void
// ConnectionManagerTest::testDeclineICERequest()
// {

//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });


//     std::condition_variable cv;
//     bool successfullyConnected = false;
//     bool successfullyReceive = false;
//     bool receiverConnected = false;

//     bobAccount->connectionManager().onChannelRequest(
//         [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });

//     bobAccount->connectionManager().onICERequest([&](const DeviceId&) {
//         successfullyReceive = true;
//         return false;  //???????????????????????? is this the point?
//     });

//     bobAccount->connectionManager().onConnectionReady(
//         [&receiverConnected](const DeviceId&,
//                              const std::string& name,
//                              std::shared_ptr<ChannelSocket> socket) {
//             receiverConnected = socket && (name == "git://*");
//         });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "git://*",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });

//     cv.wait_for(lk, 30s);
//     CPPUNIT_ASSERT(successfullyReceive);
//     CPPUNIT_ASSERT(!receiverConnected);
//     CPPUNIT_ASSERT(!successfullyConnected);
// }

// //I think you testing something other than the current class!
// /*
// void
// ConnectionManagerTest::testChannelRcvShutdown()
// {
//     auto aliceAccount = Manager::instance().getAccount<JamiAccount>(aliceId);
//     auto bobAccount = Manager::instance().getAccount<JamiAccount>(bobId);
//     auto bobDeviceId = DeviceId(std::string(bobAccount->currentDeviceId()));

//     bobAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });
//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });

//     std::mutex mtx;
//     std::unique_lock<std::mutex> lk {mtx};
//     std::condition_variable cv;
//     bool successfullyConnected = false;
//     bool shutdownReceived = false;

//     std::shared_ptr<ChannelSocket> bobSock;

//     bobAccount->connectionManager().onChannelRequest(
//         [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });

//     bobAccount->connectionManager().onConnectionReady(
//         [&](const DeviceId& did, const std::string& name, std::shared_ptr<ChannelSocket> socket) {
//             if (socket && name == "git://*" && did != bobDeviceId) {
//                 bobSock = socket;
//                 cv.notify_one();
//             }
//         });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "git://*",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             socket->onShutdown([&] {
//                                                                 shutdownReceived = true;
//                                                                 cv.notify_one();
//                                                             });
//                                                             successfullyConnected = true;
//                                                             cv.notify_one();
//                                                         }
//                                                     });

//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return bobSock && successfullyConnected; }));
//     bobSock->shutdown();
//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return shutdownReceived; }));
// }
// */
// void
// ConnectionManagerTest::testChannelRcvShutdown()
// {

//     std::condition_variable cv;
//     bool successfullyConnected = false;
//     bool shutdownReceived = false;

//     std::shared_ptr<ChannelSocket> bobSock;

//     bobAccount->connectionManager().onChannelRequest(
//         [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });

//     bobAccount->connectionManager().onConnectionReady(
//         [&](const DeviceId& did, const std::string& name, std::shared_ptr<ChannelSocket> socket) {
//             if (socket && name == "git://*" && did != bobDeviceId) {
//                 bobSock = socket;
//                 cv.notify_one();
//             }
//         });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "git://*",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             socket->onShutdown([&] {
//                                                                 shutdownReceived = true;
//                                                                 cv.notify_one();
//                                                             });
//                                                             successfullyConnected = true;
//                                                             cv.notify_one();
//                                                         }
//                                                     });


//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return bobSock && successfullyConnected; }));

//     bobSock->shutdown();

//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return shutdownReceived; }));
// }

// //I think you testing something other than the current class!
// void
// ConnectionManagerTest::testChannelSenderShutdown()
// {
//     auto aliceAccount = Manager::instance().getAccount<JamiAccount>(aliceId);
//     auto bobAccount = Manager::instance().getAccount<JamiAccount>(bobId);
//     auto bobDeviceId = DeviceId(std::string(bobAccount->currentDeviceId()));

//     bobAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });
//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });

//     std::mutex mtx;
//     std::unique_lock<std::mutex> lk {mtx};
//     std::condition_variable rcv, scv;
//     bool successfullyConnected = false;
//     bool successfullyReceive = false;
//     bool receiverConnected = false;
//     bool shutdownReceived = false;

//     bobAccount->connectionManager().onChannelRequest(
//         [&successfullyReceive](const std::shared_ptr<dht::crypto::Certificate>&,
//                                const std::string& name) {
//             successfullyReceive = name == "git://*";
//             return true;
//         });

//     bobAccount->connectionManager().onConnectionReady(
//         [&](const DeviceId&, const std::string& name, std::shared_ptr<ChannelSocket> socket) {
//             if (socket) {
//                 socket->onShutdown([&] {
//                     shutdownReceived = true;
//                     scv.notify_one();
//                 });
//             }
//             receiverConnected = socket && (name == "git://*");
//         });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "git://*",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             successfullyConnected = true;
//                                                             rcv.notify_one();
//                                                             socket->shutdown();
//                                                         }
//                                                     });

//     rcv.wait_for(lk, 30s);
//     scv.wait_for(lk, 30s);
//     CPPUNIT_ASSERT(shutdownReceived);
//     CPPUNIT_ASSERT(successfullyReceive);
//     CPPUNIT_ASSERT(successfullyConnected);
//     CPPUNIT_ASSERT(receiverConnected);
// }

// //how to get URI?
// //The call back function has different logic. Also, there are cuncurrenct tasks here. Please explain them.
// void
// ConnectionManagerTest::testCloseConnectionWith()
// {

    
//     auto bobUri = bobAccount->getUsername();

//     std::condition_variable rcv, scv;
//     std::atomic_int events(0);
//     bool successfullyConnected = false;
//     bool successfullyReceive = false;
//     bool receiverConnected = false;

//     auto chanlReqCalBack =  [&successfullyReceive]
//                             (const std::shared_ptr<dht::crypto::Certificate>&, const std::string& name) 
//                             {
//                                 successfullyReceive = name == "git://*";
//                                 return true;
//                             };

//     bobConMngr.onChannelRequest(chanlReqCalBack);

    
//     auto conctReadyCalBack =[&]
//                             (const DeviceId&, const std::string& name, std::shared_ptr<ChannelSocket> socket) 
//                             {
//                                 if (socket) {
//                                     socket->onShutdown([&] {
//                                     events += 1;// this is an atomic variable why not using atomic operation i.e event.fetch_add(1)
//                                     scv.notify_one();
//                                     });
//                                 }
//                                 receiverConnected = socket && (name == "git://*");
//                             }

//     bobConMngr.onConnectionReady(conctReadyCalBack);


//     auto conctDevicCalBack =[&]
//                             (std::shared_ptr<ChannelSocket> socket,const DeviceId&) 
//                             {
//                                 if (socket) {
//                                     socket->onShutdown([&] {
//                                         events += 1;
//                                         scv.notify_one();
//                                     });
//                                     successfullyConnected = true;
//                                     rcv.notify_one();
//                                 }
//                             };

//     alicConMngr.connectDevice(bobDevicId, "git://*", conctDevicCalBack);

    
//     CPPUNIT_ASSERT(rcv.wait_for(lk, 60s, [&] {
//         return successfullyReceive && successfullyConnected && receiverConnected;
//     }));

//     // This should trigger onShutdown
//     alicConMngr.closeConnectionsWith(bobUri);

//     CPPUNIT_ASSERT(scv.wait_for(lk, 60s, [&] {
//         return events == 2;
//     }));
// }

// //explain algorithm
// void
// ConnectionManagerTest::testShutdownCallbacks()
// {

//     auto aliceUri = aliceAccount->getUsername();

//     std::condition_variable rcv, chan2cv;
//     bool successfullyConnected = false;
//     bool successfullyReceive = false;
//     bool receiverConnected = false;

//     auto chanlReqCalBack =  [&successfullyReceive, &chan2cv]
//                             (const std::shared_ptr<dht::crypto::Certificate>&, const std::string& name) 
//                             {
//                                 if (name == "1") {
//                                     successfullyReceive = true;
//                                 } else {
//                                     chan2cv.notify_one();
//                                     // Do not return directly. Let the connection be closed
//                                     std::this_thread::sleep_for(10s);
//                                 }
//                                 return true;
//                             };

//     bobConMngr.onChannelRequest(chanlReqCalBack);


//     auto conctReadyCalBack =[&]
//                             (const DeviceId&, const std::string& name, std::shared_ptr<ChannelSocket> socket) 
//                             {
//                                 receiverConnected = socket && (name == "1");
//                             };

//     bobConMngr.onConnectionReady(conctReadyCalBack);


//     auto conctDevicCalBack =[&]
//                             (std::shared_ptr<ChannelSocket> socket, const DeviceId&) 
//                             {
//                                 if (socket) {
//                                     successfullyConnected = true;
//                                     rcv.notify_one();
//                                 }
//                             };

//     alicConMngr.connectDevice(bobDeviceId, "1", conctDevicCalBack);


//     // Connect first channel. This will initiate a mx sock ?????????????????????????????????????????????????????
//     CPPUNIT_ASSERT(rcv.wait_for(lk, 30s, [&] {
//         return successfullyReceive && successfullyConnected && receiverConnected;
//     }));

//     // Connect another channel, but close the connection
//     bool channel2NotConnected = false;


//     auto conctDevicCalBack2 =[&]
//                             (std::shared_ptr<ChannelSocket> socket, const DeviceId&) 
//                             {
//                                 channel2NotConnected = !socket;
//                                 rcv.notify_one();
//                             };

//     alicConMngr.connectDevice(bobDeviceId, "2", conctDevicCalBack2);

//     chan2cv.wait_for(lk, 30s);

//     // This should trigger onShutdown for second callback
//     bobConMngr.closeConnectionsWith(aliceUri);
//     CPPUNIT_ASSERT(rcv.wait_for(lk, 30s, [&] { return channel2NotConnected; }));
// }

// //What is the story?
// void
// ConnectionManagerTest::testFloodSocket()
// {
//     auto aliceAccount = Manager::instance().getAccount<JamiAccount>(aliceId);
//     auto bobAccount = Manager::instance().getAccount<JamiAccount>(bobId);
//     auto bobDeviceId = DeviceId(std::string(bobAccount->currentDeviceId()));
//     bobAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });
//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });

//     std::mutex mtx;
//     std::unique_lock<std::mutex> lk {mtx};
//     std::condition_variable cv;
//     bool successfullyConnected = false;
//     bool successfullyReceive = false;
//     bool receiverConnected = false;
//     std::shared_ptr<ChannelSocket> rcvSock1, rcvSock2, rcvSock3, sendSock, sendSock2, sendSock3;

//     bobAccount->connectionManager().onChannelRequest(
//         [&successfullyReceive](const std::shared_ptr<dht::crypto::Certificate>&,
//                                const std::string& name) {
//             successfullyReceive = name == "1";
//             return true;
//         });
//     bobAccount->connectionManager().onConnectionReady(
//         [&](const DeviceId&, const std::string& name, std::shared_ptr<ChannelSocket> socket) {
//             receiverConnected = socket != nullptr;
//             if (name == "1")
//                 rcvSock1 = socket;
//             else if (name == "2")
//                 rcvSock2 = socket;
//             else if (name == "3")
//                 rcvSock3 = socket;
//         });
//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "1",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             sendSock = socket;
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });
//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] {
//         return successfullyReceive && successfullyConnected && receiverConnected;
//     }));
//     CPPUNIT_ASSERT(receiverConnected);
//     successfullyConnected = false;
//     receiverConnected = false;
//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "2",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             sendSock2 = socket;
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });
//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return successfullyConnected && receiverConnected; }));
//     successfullyConnected = false;
//     receiverConnected = false;
//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "3",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             sendSock3 = socket;
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });
//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return successfullyConnected && receiverConnected; }));
   
//     std::mutex mtxRcv {};
//     std::string alphabet, shouldRcv, rcv1, rcv2, rcv3;
//     for (int i = 0; i < 100; ++i)
//         alphabet += "QWERTYUIOPASDFGHJKLZXCVBNM";

//         // Qx8000
//         // Wx8000
//         // Ex8000
//         // ...
//         // Qx8000
//         // Wx8000
//         // Ex8000
//         // ... x 99
//     rcvSock1->setOnRecv([&](const uint8_t* buf, size_t len) {
//         rcv1 += std::string(buf, buf + len);
//         return len;
//     });
//     rcvSock2->setOnRecv([&](const uint8_t* buf, size_t len) {
//         rcv2 += std::string(buf, buf + len);
//         return len;
//     });
//     rcvSock3->setOnRecv([&](const uint8_t* buf, size_t len) {
//         rcv3 += std::string(buf, buf + len);
//         return len;
//     });
//     for (uint64_t i = 0; i < alphabet.size(); ++i) {
//         auto send = std::string(8000, alphabet[i]);
//         shouldRcv += send;
//         std::error_code ec;
//         sendSock->write(reinterpret_cast<unsigned char*>(send.data()), send.size(), ec);
//         sendSock2->write(reinterpret_cast<unsigned char*>(send.data()), send.size(), ec);
//         sendSock3->write(reinterpret_cast<unsigned char*>(send.data()), send.size(), ec);
//         CPPUNIT_ASSERT(!ec);
//     }
//     CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] {
//         return shouldRcv == rcv1 && shouldRcv == rcv2 && shouldRcv == rcv3;
//     }));
// }

// void
// ConnectionManagerTest::testDestroyWhileSending()
// {
//     // Same as test before, but destroy the accounts while sending.
//     // This test if a segfault occurs
//     auto aliceAccount = Manager::instance().getAccount<JamiAccount>(aliceId);
//     auto bobAccount = Manager::instance().getAccount<JamiAccount>(bobId);
//     auto bobDeviceId = DeviceId(std::string(bobAccount->currentDeviceId()));
//     bobAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });
//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });
//     std::mutex mtx;
//     std::unique_lock<std::mutex> lk {mtx};
//     std::condition_variable cv;
//     bool successfullyConnected = false;
//     bool successfullyReceive = false;
//     bool receiverConnected = false;
//     std::shared_ptr<ChannelSocket> rcvSock1, rcvSock2, rcvSock3, sendSock, sendSock2, sendSock3;
//     bobAccount->connectionManager().onChannelRequest(
//         [&successfullyReceive](const std::shared_ptr<dht::crypto::Certificate>&,
//                                const std::string& name) {
//             successfullyReceive = name == "1";
//             return true;
//         });
//     bobAccount->connectionManager().onConnectionReady(
//         [&](const DeviceId&, const std::string& name, std::shared_ptr<ChannelSocket> socket) {
//             receiverConnected = socket != nullptr;
//             if (name == "1")
//                 rcvSock1 = socket;
//             else if (name == "2")
//                 rcvSock2 = socket;
//             else if (name == "3")
//                 rcvSock3 = socket;
//         });
//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "1",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             sendSock = socket;
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });
//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] {
//         return successfullyReceive && successfullyConnected && receiverConnected;
//     }));
//     successfullyConnected = false;
//     receiverConnected = false;
//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "2",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             sendSock2 = socket;
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });
//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return successfullyConnected && receiverConnected; }));
//     successfullyConnected = false;
//     receiverConnected = false;
//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "3",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             sendSock3 = socket;
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });
//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return successfullyConnected && receiverConnected; }));
//     std::mutex mtxRcv {};
//     std::string alphabet;
//     for (int i = 0; i < 100; ++i)
//         alphabet += "QWERTYUIOPASDFGHJKLZXCVBNM";
//     rcvSock1->setOnRecv([&](const uint8_t*, size_t len) { return len; });
//     rcvSock2->setOnRecv([&](const uint8_t*, size_t len) { return len; });
//     rcvSock3->setOnRecv([&](const uint8_t*, size_t len) { return len; });
//     for (uint64_t i = 0; i < alphabet.size(); ++i) {
//         auto send = std::string(8000, alphabet[i]);
//         std::error_code ec;
//         sendSock->write(reinterpret_cast<unsigned char*>(send.data()), send.size(), ec);
//         sendSock2->write(reinterpret_cast<unsigned char*>(send.data()), send.size(), ec);
//         sendSock3->write(reinterpret_cast<unsigned char*>(send.data()), send.size(), ec);
//         CPPUNIT_ASSERT(!ec);
//     }

    

//     // No need to wait, immediately destroy, no segfault must occurs
// }


// //why you don't use this function in other test units to validate a test?
// /*
// void
// ConnectionManagerTest::testIsConnecting()
// {
//     auto aliceAccount = Manager::instance().getAccount<JamiAccount>(aliceId);
//     auto bobAccount = Manager::instance().getAccount<JamiAccount>(bobId);
//     auto bobDeviceId = DeviceId(std::string(bobAccount->currentDeviceId()));

//     bobAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });
//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });

//     std::mutex mtx;
//     std::unique_lock<std::mutex> lk {mtx};
//     std::condition_variable cv;
//     bool successfullyConnected = false, successfullyReceive = false;

//     bobAccount->connectionManager().onChannelRequest(
//         [&](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) {
//             successfullyReceive = true;
//             cv.notify_one();
//             std::this_thread::sleep_for(2s);
//             return true;
//         });

//     CPPUNIT_ASSERT(!aliceAccount->connectionManager().isConnecting(bobDeviceId, "sip"));

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "sip",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });
//     // connectDevice is full async, so isConnecting will be true after a few ms.
//     CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] { return successfullyReceive; }));
//     CPPUNIT_ASSERT(aliceAccount->connectionManager().isConnecting(bobDeviceId, "sip"));
//     CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] { return successfullyConnected; }));
//     std::this_thread::sleep_for(
//         std::chrono::milliseconds(100)); // Just to wait for the callback to finish
//     CPPUNIT_ASSERT(!aliceAccount->connectionManager().isConnecting(bobDeviceId, "sip"));
// }
// */
// void
// ConnectionManagerTest::testIsConnecting()
// {

//     std::condition_variable cv;
//     bool successfullyConnected = false;
//     bool successfullyReceive = false;

//     bobAccount->connectionManager().onChannelRequest(
//         [&](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) {
//             successfullyReceive = true;
//             cv.notify_one();
//             std::this_thread::sleep_for(2s);
//             return true;
//         });

//     CPPUNIT_ASSERT(!aliceAccount->connectionManager().isConnecting(bobDeviceId, "sip"));

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "sip",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });

//     // connectDevice is full async, so isConnecting will be true after a few ms.
//     CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] { return successfullyReceive; }));
//     CPPUNIT_ASSERT(aliceAccount->connectionManager().isConnecting(bobDeviceId, "sip"));
//     CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] { return successfullyConnected; }));
//     std::this_thread::sleep_for(
//         std::chrono::milliseconds(100)); // Just to wait for the callback to finish
//     CPPUNIT_ASSERT(!aliceAccount->connectionManager().isConnecting(bobDeviceId, "sip"));
// }



// void
// ConnectionManagerTest::testCanSendBeacon()
// {
//     auto aliceAccount = Manager::instance().getAccount<JamiAccount>(aliceId);
//     auto bobAccount = Manager::instance().getAccount<JamiAccount>(bobId);
//     auto bobDeviceId = DeviceId(std::string(bobAccount->currentDeviceId()));

//     bobAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });
//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });

//     std::mutex mtx;
//     std::unique_lock<std::mutex> lk {mtx};
//     std::condition_variable cv;
//     bool successfullyConnected = false;

//     std::shared_ptr<MultiplexedSocket> aliceSocket, bobSocket;
//     bobAccount->connectionManager().onChannelRequest(
//         [&](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });
//     bobAccount->connectionManager().onConnectionReady(
//         [&](const DeviceId&, const std::string&, std::shared_ptr<ChannelSocket> socket) {
//             if (socket && socket->name() == "sip")
//                 bobSocket = socket->underlyingSocket();
//             cv.notify_one();
//         });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "sip",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             aliceSocket = socket->underlyingSocket();
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });
//     // connectDevice is full async, so isConnecting will be true after a few ms.
//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return aliceSocket && bobSocket && successfullyConnected; }));
//     CPPUNIT_ASSERT(aliceSocket->canSendBeacon());

//     // Because onConnectionReady is true before version is sent, we can wait a bit
//     // before canSendBeacon is true.
//     auto start = std::chrono::steady_clock::now();
//     auto aliceCanSendBeacon = false;
//     auto bobCanSendBeacon = false;
//     do {
//         aliceCanSendBeacon = aliceSocket->canSendBeacon();
//         bobCanSendBeacon = bobSocket->canSendBeacon();
//         if (!bobCanSendBeacon || !aliceCanSendBeacon)
//             std::this_thread::sleep_for(1s);
//     } while ((not bobCanSendBeacon or not aliceCanSendBeacon)
//              and std::chrono::steady_clock::now() - start < 5s);

//     CPPUNIT_ASSERT(bobCanSendBeacon && aliceCanSendBeacon);
// }

// void
// ConnectionManagerTest::testCannotSendBeacon()
// {
//     auto aliceAccount = Manager::instance().getAccount<JamiAccount>(aliceId);
//     auto bobAccount = Manager::instance().getAccount<JamiAccount>(bobId);
//     auto bobDeviceId = DeviceId(std::string(bobAccount->currentDeviceId()));

//     bobAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });
//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });

//     std::mutex mtx;
//     std::unique_lock<std::mutex> lk {mtx};
//     std::condition_variable cv;
//     bool successfullyConnected = false;

//     std::shared_ptr<MultiplexedSocket> aliceSocket, bobSocket;
//     bobAccount->connectionManager().onChannelRequest(
//         [&](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });
//     bobAccount->connectionManager().onConnectionReady(
//         [&](const DeviceId&, const std::string&, std::shared_ptr<ChannelSocket> socket) {
//             if (socket && socket->name() == "sip")
//                 bobSocket = socket->underlyingSocket();
//             cv.notify_one();
//         });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "sip",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             aliceSocket = socket->underlyingSocket();
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });
//     // connectDevice is full async, so isConnecting will be true after a few ms.
//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return aliceSocket && bobSocket; }));

//     int version = 1412;
//     bobSocket->setOnVersionCb([&](auto v) {
//         version = v;
//         cv.notify_one();
//     });
//     aliceSocket->setVersion(0);
//     aliceSocket->sendVersion();
//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return version == 0; }));
//     CPPUNIT_ASSERT(!bobSocket->canSendBeacon());
// }

// void
// ConnectionManagerTest::testConnectivityChangeTriggerBeacon()
// {
//     auto aliceAccount = Manager::instance().getAccount<JamiAccount>(aliceId);
//     auto bobAccount = Manager::instance().getAccount<JamiAccount>(bobId);
//     auto bobDeviceId = DeviceId(std::string(bobAccount->currentDeviceId()));

//     bobAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });
//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });

//     std::mutex mtx;
//     std::unique_lock<std::mutex> lk {mtx};
//     std::condition_variable cv;
//     bool successfullyConnected = false;

//     std::shared_ptr<MultiplexedSocket> aliceSocket, bobSocket;
//     bobAccount->connectionManager().onChannelRequest(
//         [&](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });
//     bobAccount->connectionManager().onConnectionReady(
//         [&](const DeviceId&, const std::string&, std::shared_ptr<ChannelSocket> socket) {
//             if (socket && socket->name() == "sip")
//                 bobSocket = socket->underlyingSocket();
//             cv.notify_one();
//         });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "sip",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             aliceSocket = socket->underlyingSocket();
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });
//     // connectDevice is full async, so isConnecting will be true after a few ms.
//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return aliceSocket && bobSocket; }));

//     bool hasRequest = false;
//     bobSocket->setOnBeaconCb([&](auto p) {
//         if (p)
//             hasRequest = true;
//         cv.notify_one();
//     });
//     aliceAccount->connectionManager().connectivityChanged();
//     CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return hasRequest; }));
// }

// void
// ConnectionManagerTest::testOnNoBeaconTriggersShutdown()
// {
//     auto aliceAccount = Manager::instance().getAccount<JamiAccount>(aliceId);
//     auto bobAccount = Manager::instance().getAccount<JamiAccount>(bobId);
//     auto bobDeviceId = DeviceId(std::string(bobAccount->currentDeviceId()));

//     bobAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });
//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });

//     std::mutex mtx;
//     std::unique_lock<std::mutex> lk {mtx};
//     std::condition_variable cv;
//     bool successfullyConnected = false;

//     std::shared_ptr<MultiplexedSocket> aliceSocket, bobSocket;
//     bobAccount->connectionManager().onChannelRequest(
//         [&](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });
//     bobAccount->connectionManager().onConnectionReady(
//         [&](const DeviceId&, const std::string&, std::shared_ptr<ChannelSocket> socket) {
//             if (socket && socket->name() == "sip")
//                 bobSocket = socket->underlyingSocket();
//             cv.notify_one();
//         });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "sip",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         if (socket) {
//                                                             aliceSocket = socket->underlyingSocket();
//                                                             successfullyConnected = true;
//                                                         }
//                                                         cv.notify_one();
//                                                     });
//     // connectDevice is full async, so isConnecting will be true after a few ms.
//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return aliceSocket && bobSocket; }));

//     bool isClosed = false;
//     aliceSocket->onShutdown([&] {
//         isClosed = true;
//         cv.notify_one();
//     });
//     bobSocket->answerToBeacon(false);
//     aliceAccount->connectionManager().connectivityChanged();
//     CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return isClosed; }));*/
// }



// //why you didn't invoke on Channel request?
// void
// ConnectionManagerTest::testShutdownWhileNegotiating()
// {

//     std::condition_variable cv;
//     bool successfullyReceive = false;
//     bool notConnected = false;

//     aliceAccount->connectionManager().onICERequest([](const DeviceId&) { return true; });

// //Why???????????
//     bobAccount->connectionManager().onICERequest([&](const DeviceId&) {
//         successfullyReceive = true;
//         cv.notify_one();
//         return true;
//     });

//     aliceAccount->connectionManager().connectDevice(bobDeviceId,
//                                                     "git://*",
//                                                     [&](std::shared_ptr<ChannelSocket> socket,
//                                                         const DeviceId&) {
//                                                         notConnected = !socket;
//                                                         cv.notify_one();
//                                                     });

//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return successfullyReceive; }));
    

//     aliceAccount->connectionManager().reset(); //use it but check it first
//     Manager::instance().setAccountActive(aliceId, false, true);//?????????????????????????????????????

//     CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return notConnected; }));
// }

} // namespace test
} // namespace jami

JAMI_TEST_RUNNER(jami::test::ConnectionManagerTest::name())

