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
#include <cppunit/TestAssert.h>
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>
#include <filesystem>

#include "test_runner.h"
#include "certstore.h"

namespace dhtnet {
namespace test {

class CertStoreTest : public CppUnit::TestFixture
{
public:
    CertStoreTest()
    {
    }
    ~CertStoreTest() { }
    static std::string name() { return "certstore"; }
    void setUp();
    void tearDown();

    std::shared_ptr<tls::CertificateStore> aliceCertStore;
    std::shared_ptr<tls::TrustStore> aliceTrustStore;
private:
    void trustStoreTest();
    void getCertificateWithSplitted();
    void testBannedParent();

    CPPUNIT_TEST_SUITE(CertStoreTest);
    CPPUNIT_TEST(trustStoreTest);
    CPPUNIT_TEST(getCertificateWithSplitted);
    CPPUNIT_TEST(testBannedParent);
    CPPUNIT_TEST_SUITE_END();
};

CPPUNIT_TEST_SUITE_NAMED_REGISTRATION(CertStoreTest, CertStoreTest::name());

void
CertStoreTest::setUp()
{
    aliceCertStore = std::make_shared<tls::CertificateStore>("aliceCertStore", nullptr);
    aliceTrustStore = std::make_shared<tls::TrustStore>(*aliceCertStore);
}

void
CertStoreTest::tearDown()
{
    std::filesystem::remove_all("aliceCertStore");
    aliceCertStore.reset();
    aliceTrustStore.reset();
}

void
CertStoreTest::trustStoreTest()
{
    auto ca = dht::crypto::generateIdentity("test CA");
    auto account = dht::crypto::generateIdentity("test account", ca, 4096, true);
    auto device = dht::crypto::generateIdentity("test device", account);
    auto device2 = dht::crypto::generateIdentity("test device 2", account);
    auto storeSize = aliceCertStore->getPinnedCertificates().size();
    auto id = ca.second->getId().toString();
    auto pinned = aliceCertStore->getPinnedCertificates();
    CPPUNIT_ASSERT(std::find_if(pinned.begin(), pinned.end(), [&](auto v) { return v == id; })
                   == pinned.end());

    // Test certificate status
    auto certAllowed = aliceTrustStore->getCertificatesByStatus(
        dhtnet::tls::TrustStore::PermissionStatus::ALLOWED);
    CPPUNIT_ASSERT(
        std::find_if(certAllowed.begin(), certAllowed.end(), [&](auto v) { return v == id; })
        == certAllowed.end());
    CPPUNIT_ASSERT(aliceTrustStore->getCertificateStatus(id)
                   == dhtnet::tls::TrustStore::PermissionStatus::UNDEFINED);
    aliceTrustStore->setCertificateStatus(ca.second, dhtnet::tls::TrustStore::PermissionStatus::ALLOWED);
    certAllowed = aliceTrustStore->getCertificatesByStatus(
        dhtnet::tls::TrustStore::PermissionStatus::ALLOWED);
    CPPUNIT_ASSERT(
        std::find_if(certAllowed.begin(), certAllowed.end(), [&](auto v) { return v == id; })
        != certAllowed.end());
    CPPUNIT_ASSERT(aliceTrustStore->getCertificateStatus(id)
                   == dhtnet::tls::TrustStore::PermissionStatus::ALLOWED);
    aliceTrustStore->setCertificateStatus(ca.second, dhtnet::tls::TrustStore::PermissionStatus::UNDEFINED);
    CPPUNIT_ASSERT(aliceTrustStore->getCertificateStatus(id)
                   == dhtnet::tls::TrustStore::PermissionStatus::UNDEFINED);
    aliceTrustStore->setCertificateStatus(ca.second, dhtnet::tls::TrustStore::PermissionStatus::ALLOWED);
    CPPUNIT_ASSERT(aliceTrustStore->getCertificateStatus(id)
                   == dhtnet::tls::TrustStore::PermissionStatus::ALLOWED);

    // Test getPinnedCertificates
    pinned = aliceCertStore->getPinnedCertificates();
    CPPUNIT_ASSERT(pinned.size() == storeSize + 2);
    CPPUNIT_ASSERT(std::find_if(pinned.begin(), pinned.end(), [&](auto v) { return v == id; })
                   != pinned.end());

    // Test findCertificateByUID & findIssuer
    CPPUNIT_ASSERT(!aliceCertStore->findCertificateByUID("NON_EXISTING_ID"));
    auto cert = aliceCertStore->findCertificateByUID(id);
    CPPUNIT_ASSERT(cert);
    auto issuer = aliceCertStore->findIssuer(cert);
    CPPUNIT_ASSERT(issuer);
    CPPUNIT_ASSERT(issuer->getId().toString() == id);

    // Test is allowed
    CPPUNIT_ASSERT(aliceTrustStore->isAllowed(*ca.second));
    CPPUNIT_ASSERT(aliceTrustStore->isAllowed(*account.second));
    CPPUNIT_ASSERT(aliceTrustStore->isAllowed(*device.second));

    // Ban device
    aliceTrustStore->setCertificateStatus(device.second, dhtnet::tls::TrustStore::PermissionStatus::BANNED);
    CPPUNIT_ASSERT(aliceTrustStore->getCertificateStatus(device.second->getId().toString())
                   == dhtnet::tls::TrustStore::PermissionStatus::BANNED);
    CPPUNIT_ASSERT(aliceTrustStore->getCertificateStatus(id)
                   == dhtnet::tls::TrustStore::PermissionStatus::ALLOWED);

    CPPUNIT_ASSERT(aliceTrustStore->isAllowed(*ca.second));
    CPPUNIT_ASSERT(aliceTrustStore->isAllowed(*account.second));
    CPPUNIT_ASSERT(not aliceTrustStore->isAllowed(*device.second));

    // Ban account
    aliceTrustStore->setCertificateStatus(account.second, dhtnet::tls::TrustStore::PermissionStatus::BANNED);
    CPPUNIT_ASSERT(aliceTrustStore->getCertificateStatus(account.second->getId().toString())
                   == dhtnet::tls::TrustStore::PermissionStatus::BANNED);
    CPPUNIT_ASSERT(aliceTrustStore->isAllowed(*ca.second));
    CPPUNIT_ASSERT(not aliceTrustStore->isAllowed(*account.second));
    CPPUNIT_ASSERT(not aliceTrustStore->isAllowed(*device2.second));

    // Unban account
    aliceTrustStore->setCertificateStatus(account.second,
                                    dhtnet::tls::TrustStore::PermissionStatus::ALLOWED);
    CPPUNIT_ASSERT(aliceTrustStore->getCertificateStatus(account.second->getId().toString())
                   == dhtnet::tls::TrustStore::PermissionStatus::ALLOWED);
    CPPUNIT_ASSERT(aliceTrustStore->isAllowed(*ca.second));
    CPPUNIT_ASSERT(aliceTrustStore->isAllowed(*account.second));
    CPPUNIT_ASSERT(aliceTrustStore->isAllowed(*device2.second));

    // Ban CA
    aliceTrustStore->setCertificateStatus(ca.second, dhtnet::tls::TrustStore::PermissionStatus::BANNED);
    CPPUNIT_ASSERT(aliceTrustStore->getCertificateStatus(ca.second->getId().toString())
                   == dhtnet::tls::TrustStore::PermissionStatus::BANNED);
    CPPUNIT_ASSERT(not aliceTrustStore->isAllowed(*ca.second));
    CPPUNIT_ASSERT(not aliceTrustStore->isAllowed(*account.second));
    CPPUNIT_ASSERT(not aliceTrustStore->isAllowed(*device2.second));

    aliceTrustStore->setCertificateStatus(ca.second, dhtnet::tls::TrustStore::PermissionStatus::BANNED);
    CPPUNIT_ASSERT(aliceTrustStore->getCertificateStatus(ca.second->getId().toString())
                   == dhtnet::tls::TrustStore::PermissionStatus::BANNED);

    // Test unpin
    aliceCertStore->unpinCertificate(id);
    pinned = aliceCertStore->getPinnedCertificates();
    CPPUNIT_ASSERT(std::find_if(pinned.begin(), pinned.end(), [&](auto v) { return v == id; })
                   == pinned.end());

    // Test statusToStr
    /*CPPUNIT_ASSERT(strcmp(dhtnet::tls::statusToStr(dhtnet::tls::TrustStatus::TRUSTED),
                          libdhtnet::Certificate::TrustStatus::TRUSTED)
                   == 0);
    CPPUNIT_ASSERT(strcmp(dhtnet::tls::statusToStr(dhtnet::tls::TrustStatus::UNTRUSTED),
                          libdhtnet::Certificate::TrustStatus::UNTRUSTED)
                   == 0);*/
}

void
CertStoreTest::getCertificateWithSplitted()
{
    auto ca = dht::crypto::generateIdentity("test CA");
    auto account = dht::crypto::generateIdentity("test account", ca, 4096, true);
    auto device = dht::crypto::generateIdentity("test device", account);

    auto caCert = std::make_shared<dht::crypto::Certificate>(ca.second->toString(false));
    auto accountCert = std::make_shared<dht::crypto::Certificate>(account.second->toString(false));
    auto devicePartialCert = std::make_shared<dht::crypto::Certificate>(
        device.second->toString(false));

    aliceCertStore->pinCertificate(caCert);
    aliceCertStore->pinCertificate(accountCert);
    aliceCertStore->pinCertificate(devicePartialCert);

    auto fullCert = aliceCertStore->getCertificate(device.second->getId().toString());
    CPPUNIT_ASSERT(fullCert->issuer && fullCert->issuer->getUID() == accountCert->getUID());
    CPPUNIT_ASSERT(fullCert->issuer->issuer
                   && fullCert->issuer->issuer->getUID() == caCert->getUID());
}

void
CertStoreTest::testBannedParent()
{
    auto ca = dht::crypto::generateIdentity("test CA");
    auto account = dht::crypto::generateIdentity("test account", ca, 4096, true);
    auto device = dht::crypto::generateIdentity("test device", account);
    auto device2 = dht::crypto::generateIdentity("test device 2", account);
    auto id = ca.second->getId().toString();
    auto pinned = aliceCertStore ->getPinnedCertificates();
    CPPUNIT_ASSERT(std::find_if(pinned.begin(), pinned.end(), [&](auto v) { return v == id; })
                   == pinned.end());

    // Ban account
    aliceTrustStore->setCertificateStatus(account.second, dhtnet::tls::TrustStore::PermissionStatus::BANNED);
    CPPUNIT_ASSERT(aliceTrustStore->getCertificateStatus(account.second->getId().toString())
                   == dhtnet::tls::TrustStore::PermissionStatus::BANNED);
    CPPUNIT_ASSERT(not aliceTrustStore->isAllowed(*account.second));
    CPPUNIT_ASSERT(not aliceTrustStore->isAllowed(*device2.second));
    CPPUNIT_ASSERT(not aliceTrustStore->isAllowed(*device.second));
}


} // namespace test
} // namespace dhtnet

JAMI_TEST_RUNNER(dhtnet::test::CertStoreTest::name());
