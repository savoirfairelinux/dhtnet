#include <cppunit/extensions/HelperMacros.h>

#include "upnp/upnp_context.h"
#include "../src/upnp/protocol/igd.h"
#include "../src/upnp/protocol/upnp_protocol.h"
#include "test_runner.h"

#include <asio.hpp>
#include <future>

namespace dhtnet {
namespace upnp {

class TestIgd : public IGD
{
public:
    explicit TestIgd(NatProtocolType type)
        : IGD(type)
    {
        setLocalIp(IpAddr("192.0.2.1"));
        setPublicIp(IpAddr("198.51.100.1"));
        setValid(true);
    }
    const std::string toString() const override { return "test-igd"; }
};

class TestProtocol : public UPnPProtocol
{
public:
    explicit TestProtocol(NatProtocolType type)
        : UPnPProtocol(nullptr)
        , igd(std::make_shared<TestIgd>(type))
    {}
    NatProtocolType getProtocol() const override { return igd->getProtocol(); }
    char const* getProtocolName() const override { return "UPNP"; }
    void clearIgds(bool) override {}
    void searchForIgd() override {}
    std::list<std::shared_ptr<IGD>> getIgdList() const override
    {
        return isReady() ? std::list {igd} : std::list<std::shared_ptr<IGD>> {};
    }
    bool isReady() const override { return ready && igd->isValid(); }
    void requestMappingAdd(const Mapping& mapping) override
    {
        adds.emplace_back(mapping);
        if (auto callback = std::move(onAdd))
            callback();
    }
    void requestMappingRenew(const Mapping& mapping) override { renewals.emplace_back(mapping); }
    void requestMappingRemove(const Mapping&) override {}
    void setObserver(UpnpMappingObserver* value) override { observer = value; }
    const IpAddr getHostAddress() const override { return IpAddr("192.0.2.2"); }
    void terminate() override {}

    void failAdd() { observer->onMappingRequestFailed(adds.back()); }
    void completeAdd()
    {
        Mapping response(adds.back());
        response.setInternalAddress(getHostAddress().toString());
        response.setRenewalTime(sys_clock::now() + std::chrono::hours(1));
        response.setExpiryTime(sys_clock::now() + std::chrono::hours(2));
        observer->onMappingAdded(response.getIgd(), response);
    }
    void expireRenewal(const Mapping::sharedPtr_t& mapping)
    {
        mapping->setRenewalTime(sys_clock::now() - std::chrono::seconds(1));
    }
    void setExpiry(const Mapping::sharedPtr_t& mapping, sys_clock::time_point expiry)
    {
        mapping->setExpiryTime(expiry);
    }
    void completeRenewal()
    {
        Mapping response(renewals.back());
        response.setRenewalTime(sys_clock::now() + std::chrono::hours(1));
        response.setExpiryTime(sys_clock::now() + std::chrono::hours(2));
        observer->onMappingRenewed(response.getIgd(), response);
    }

    std::shared_ptr<IGD> igd;
    UpnpMappingObserver* observer {};
    std::vector<Mapping> adds;
    std::vector<Mapping> renewals;
    std::function<void()> onAdd;
    bool ready {true};
};

class UPnPContextTest : public CppUnit::TestFixture
{
public:
    static std::string name() { return "UPnPContextTest"; }
    void setUp() override
    {
        context = std::make_unique<UPnPContext>(nullptr, nullptr);
        run([this] {
            auto type = context->protocolList_.empty() ? NatProtocolType::PUPNP : context->protocolList_.begin()->first;
            protocol = std::make_shared<TestProtocol>(type);
            protocol->setObserver(context.get());
            context->protocolList_.clear();
            context->protocolList_.emplace(type, protocol);
            context->setAvailableMappingsLimits(PortType::TCP, 0, 0);
            context->setAvailableMappingsLimits(PortType::UDP, 0, 0);
            context->started_ = true;
            context->onIgdUpdated(protocol->igd, UpnpIgdEvent::ADDED);
        });
    }
    void tearDown() override
    {
        context->shutdown();
        context.reset();
    }

private:
    void run(std::function<void()> operation)
    {
        auto task = std::make_shared<std::packaged_task<void()>>(std::move(operation));
        auto done = task->get_future();
        context->dispatch([task] { (*task)(); });
        CPPUNIT_ASSERT(done.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
        done.get();
    }

    Mapping::sharedPtr_t reserve()
    {
        Mapping desired(PortType::UDP, 39173, 39173);
        desired.enableAutoUpdate(true);
        return context->reserveMapping(desired);
    }

    void retryBackoff()
    {
        run([this] {
            auto mapping = reserve();
            CPPUNIT_ASSERT(mapping);
            protocol->failAdd();
            CPPUNIT_ASSERT(mapping->getState() == MappingState::PENDING);
            context->_syncLocalMappingListWithIgd();
            context->processPendingRequests();
            context->onIgdUpdated(protocol->igd, UpnpIgdEvent::ADDED);
            CPPUNIT_ASSERT_EQUAL(std::size_t(1), protocol->adds.size());
            CPPUNIT_ASSERT_EQUAL(uint16_t(39173), mapping->getInternalPort());
            auto& retry = context->mappingRetries_.at(mapping->getMapKey());
            CPPUNIT_ASSERT(retry.delay == std::chrono::seconds(10));
            retry.nextAttempt = std::chrono::steady_clock::now();
            context->processPendingRequests();
            CPPUNIT_ASSERT_EQUAL(std::size_t(2), protocol->adds.size());
            protocol->failAdd();
            CPPUNIT_ASSERT(retry.delay == std::chrono::seconds(20));
            for (unsigned attempt = 0; attempt < 8; ++attempt) {
                retry.nextAttempt = std::chrono::steady_clock::now();
                context->processPendingRequests();
                protocol->failAdd();
                CPPUNIT_ASSERT(retry.delay <= std::chrono::seconds(60));
            }
            CPPUNIT_ASSERT(retry.delay == std::chrono::seconds(60));
            retry.nextAttempt = std::chrono::steady_clock::now();
            context->processPendingRequests();
            protocol->completeAdd();
            CPPUNIT_ASSERT(mapping->getState() == MappingState::OPEN);
            CPPUNIT_ASSERT_EQUAL(uint16_t(39173), protocol->adds.back().getInternalPort());
            CPPUNIT_ASSERT_EQUAL(uint16_t(39173), protocol->adds.back().getExternalPort());
            CPPUNIT_ASSERT(context->mappingRetries_.empty());
        });
    }

    void slowRequests()
    {
        run([this] {
            auto mapping = reserve();
            for (unsigned iteration = 0; iteration < 5; ++iteration) {
                context->processPendingRequests();
                context->_syncLocalMappingListWithIgd();
            }
            CPPUNIT_ASSERT_EQUAL(std::size_t(1), protocol->adds.size());
            CPPUNIT_ASSERT(context->mappingRetries_.empty());
            protocol->completeAdd();
            protocol->expireRenewal(mapping);
            context->renewMappings();
            context->_scheduleMappingsRenewal();
            context->renewMappings();
            context->_syncLocalMappingListWithIgd();
            CPPUNIT_ASSERT_EQUAL(std::size_t(1), protocol->renewals.size());
            CPPUNIT_ASSERT(mapping->getState() == MappingState::OPEN);
            protocol->completeRenewal();
            CPPUNIT_ASSERT(context->mappingRenewals_.empty());
            CPPUNIT_ASSERT(mapping->getState() == MappingState::OPEN);
        });
    }

    void renewalRejectedUntilExpiry()
    {
        run([this] {
            auto mapping = reserve();
            protocol->completeAdd();
            protocol->expireRenewal(mapping);
            context->renewMappings();
            protocol->observer->onMappingRequestFailed(protocol->renewals.back());
            auto& retry = context->mappingRetries_.at(mapping->getMapKey());
            auto remaining = mapping->getExpiryTime() - sys_clock::now();
            CPPUNIT_ASSERT(retry.nextAttempt - std::chrono::steady_clock::now() >= remaining);
            context->processPendingRequests();
            context->onIgdUpdated(protocol->igd, UpnpIgdEvent::ADDED);
            CPPUNIT_ASSERT_EQUAL(std::size_t(1), protocol->adds.size());
            retry.nextAttempt = std::chrono::steady_clock::now();
            context->processPendingRequests();
            CPPUNIT_ASSERT_EQUAL(std::size_t(2), protocol->adds.size());
            protocol->completeAdd();
            CPPUNIT_ASSERT(mapping->getState() == MappingState::OPEN);
            CPPUNIT_ASSERT_EQUAL(uint16_t(39173), mapping->getInternalPort());
        });
    }

    void timerRetriesWithoutIgdEvents()
    {
        auto completed = std::make_shared<std::promise<void>>();
        auto done = completed->get_future();
        run([this, completed] {
            auto mapping = reserve();
            protocol->failAdd();
            protocol->onAdd = [this, completed] {
                protocol->completeAdd();
                completed->set_value();
            };
            context->mappingRetries_.at(mapping->getMapKey()).nextAttempt = std::chrono::steady_clock::now();
            context->scheduleMappingRetries();
            protocol->ready = false;
            context->scheduleMappingRetries();
            protocol->ready = true;
            context->scheduleMappingRetries();
        });
        CPPUNIT_ASSERT(done.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
        run([this] {
            CPPUNIT_ASSERT_EQUAL(std::size_t(2), protocol->adds.size());
            auto mapping = context->getMappingWithKey(protocol->adds.back().getMapKey());
            CPPUNIT_ASSERT(mapping->getState() == MappingState::OPEN);
        });
    }

    void renewalWithoutRemainingLease()
    {
        run([this] {
            auto mapping = reserve();
            protocol->completeAdd();
            for (auto expiry : {sys_clock::now() - std::chrono::seconds(1), sys_clock::time_point::max()}) {
                protocol->expireRenewal(mapping);
                protocol->setExpiry(mapping, expiry);
                context->renewMappings();
                protocol->observer->onMappingRequestFailed(protocol->renewals.back());
                auto& retry = context->mappingRetries_.at(mapping->getMapKey());
                CPPUNIT_ASSERT(retry.nextAttempt - std::chrono::steady_clock::now() <= std::chrono::seconds(11));
                retry.nextAttempt = std::chrono::steady_clock::now();
                context->processPendingRequests();
                protocol->completeAdd();
            }
        });
    }

    void cancelRetry()
    {
        run([this] {
            auto mapping = reserve();
            protocol->failAdd();
            context->releaseMapping(*mapping);
            CPPUNIT_ASSERT(context->mappingRetries_.empty());
            CPPUNIT_ASSERT(!context->getMappingWithKey(mapping->getMapKey()));
            context->processPendingRequests();
            CPPUNIT_ASSERT_EQUAL(std::size_t(1), protocol->adds.size());
            mapping = reserve();
            protocol->failAdd();
            context->stopUpnp();
            context->onIgdUpdated(protocol->igd, UpnpIgdEvent::ADDED);
            context->processPendingRequests();
            CPPUNIT_ASSERT(context->mappingRetries_.empty());
            CPPUNIT_ASSERT(!context->isReady());
            CPPUNIT_ASSERT_EQUAL(std::size_t(2), protocol->adds.size());
        });
    }

    void replaceIgd()
    {
        run([this] {
            auto mapping = reserve();
            protocol->failAdd();
            auto previous = protocol->igd;
            previous->setValid(false);
            context->onIgdUpdated(previous, UpnpIgdEvent::REMOVED);
            context->processPendingRequests();
            CPPUNIT_ASSERT_EQUAL(std::size_t(1), protocol->adds.size());
            protocol->igd = std::make_shared<TestIgd>(protocol->getProtocol());
            context->onIgdUpdated(protocol->igd, UpnpIgdEvent::ADDED);
            CPPUNIT_ASSERT_EQUAL(std::size_t(2), protocol->adds.size());
            context->onMappingRequestFailed(protocol->adds.front());
            context->onMappingAdded(previous, protocol->adds.front());
            CPPUNIT_ASSERT(mapping->getState() == MappingState::IN_PROGRESS);
            protocol->completeAdd();
            CPPUNIT_ASSERT(mapping->getState() == MappingState::OPEN);
            CPPUNIT_ASSERT_EQUAL(uint16_t(39173), mapping->getInternalPort());
        });
    }

    void poolBackoff()
    {
        run([this] {
            context->setAvailableMappingsLimits(PortType::UDP, 1, 1);
            context->enforceAvailableMappingsLimits();
            protocol->failAdd();
            context->processPendingRequests();
            context->enforceAvailableMappingsLimits();
            CPPUNIT_ASSERT_EQUAL(std::size_t(1), protocol->adds.size());
            CPPUNIT_ASSERT(context->poolRetryDelay_[1] == std::chrono::seconds(10));
            context->poolRetryAfter_[1] = std::chrono::steady_clock::now();
            context->processPendingRequests();
            CPPUNIT_ASSERT_EQUAL(std::size_t(2), protocol->adds.size());
            protocol->failAdd();
            CPPUNIT_ASSERT(context->poolRetryDelay_[1] == std::chrono::seconds(20));
            context->poolRetryAfter_[1] = std::chrono::steady_clock::now();
            context->processPendingRequests();
            protocol->completeAdd();
            CPPUNIT_ASSERT(context->poolRetryDelay_[1] == std::chrono::seconds::zero());
        });
    }

    void reserveWithoutIgd()
    {
        run([this] {
            protocol->igd->setValid(false);
            context->onIgdUpdated(protocol->igd, UpnpIgdEvent::REMOVED);
            context->igdDiscoveryInProgress_ = false;
            auto mapping = reserve();
            CPPUNIT_ASSERT(mapping);
            CPPUNIT_ASSERT(mapping->getState() == MappingState::PENDING);
            protocol->igd = std::make_shared<TestIgd>(protocol->getProtocol());
            context->onIgdUpdated(protocol->igd, UpnpIgdEvent::ADDED);
            CPPUNIT_ASSERT_EQUAL(std::size_t(1), protocol->adds.size());
            CPPUNIT_ASSERT_EQUAL(uint16_t(39173), protocol->adds.back().getInternalPort());
        });
    }

    CPPUNIT_TEST_SUITE(UPnPContextTest);
    CPPUNIT_TEST(retryBackoff);
    CPPUNIT_TEST(slowRequests);
    CPPUNIT_TEST(renewalRejectedUntilExpiry);
    CPPUNIT_TEST(timerRetriesWithoutIgdEvents);
    CPPUNIT_TEST(renewalWithoutRemainingLease);
    CPPUNIT_TEST(cancelRetry);
    CPPUNIT_TEST(replaceIgd);
    CPPUNIT_TEST(poolBackoff);
    CPPUNIT_TEST(reserveWithoutIgd);
    CPPUNIT_TEST_SUITE_END();

    std::unique_ptr<UPnPContext> context;
    std::shared_ptr<TestProtocol> protocol;
};

CPPUNIT_TEST_SUITE_NAMED_REGISTRATION(UPnPContextTest, UPnPContextTest::name());

} // namespace upnp
} // namespace dhtnet

JAMI_TEST_RUNNER(dhtnet::upnp::UPnPContextTest::name());