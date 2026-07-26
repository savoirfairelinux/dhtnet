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
#include "fileutils.h"

namespace dhtnet {
namespace test {

class CertStoreTest : public CppUnit::TestFixture
{
public:
    CertStoreTest() {}
    ~CertStoreTest() {}
    static std::string name() { return "certstore"; }
    void setUp();
    void tearDown();

    std::shared_ptr<tls::CertificateStore> aliceCertStore;
    std::shared_ptr<tls::TrustStore> aliceTrustStore;

private:
    void trustStoreTest();
    void getCertificateWithSplitted();
    void testBannedParent();
    void testRevocationListStorage();
    void testRevocationListNumberCollision();
    void testUnpinRevocationList();
    void testLegacyRevocationListStorage();

    CPPUNIT_TEST_SUITE(CertStoreTest);
    CPPUNIT_TEST(trustStoreTest);
    CPPUNIT_TEST(getCertificateWithSplitted);
    CPPUNIT_TEST(testBannedParent);
    CPPUNIT_TEST(testRevocationListStorage);
    CPPUNIT_TEST(testRevocationListNumberCollision);
    CPPUNIT_TEST(testUnpinRevocationList);
    CPPUNIT_TEST(testLegacyRevocationListStorage);
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
    CPPUNIT_ASSERT(std::find_if(pinned.begin(), pinned.end(), [&](auto v) { return v == id; }) == pinned.end());

    // Test certificate status
    auto certAllowed = aliceTrustStore->getCertificatesByStatus(dhtnet::tls::TrustStore::PermissionStatus::ALLOWED);
    CPPUNIT_ASSERT(std::find_if(certAllowed.begin(), certAllowed.end(), [&](auto v) { return v == id; })
                   == certAllowed.end());
    CPPUNIT_ASSERT(aliceTrustStore->getCertificateStatus(id) == dhtnet::tls::TrustStore::PermissionStatus::UNDEFINED);
    aliceTrustStore->setCertificateStatus(ca.second, dhtnet::tls::TrustStore::PermissionStatus::ALLOWED);
    certAllowed = aliceTrustStore->getCertificatesByStatus(dhtnet::tls::TrustStore::PermissionStatus::ALLOWED);
    CPPUNIT_ASSERT(std::find_if(certAllowed.begin(), certAllowed.end(), [&](auto v) { return v == id; })
                   != certAllowed.end());
    CPPUNIT_ASSERT(aliceTrustStore->getCertificateStatus(id) == dhtnet::tls::TrustStore::PermissionStatus::ALLOWED);
    aliceTrustStore->setCertificateStatus(ca.second, dhtnet::tls::TrustStore::PermissionStatus::UNDEFINED);
    CPPUNIT_ASSERT(aliceTrustStore->getCertificateStatus(id) == dhtnet::tls::TrustStore::PermissionStatus::UNDEFINED);
    aliceTrustStore->setCertificateStatus(ca.second, dhtnet::tls::TrustStore::PermissionStatus::ALLOWED);
    CPPUNIT_ASSERT(aliceTrustStore->getCertificateStatus(id) == dhtnet::tls::TrustStore::PermissionStatus::ALLOWED);

    // Test getPinnedCertificates
    pinned = aliceCertStore->getPinnedCertificates();
    CPPUNIT_ASSERT(pinned.size() == storeSize + 2);
    CPPUNIT_ASSERT(std::find_if(pinned.begin(), pinned.end(), [&](auto v) { return v == id; }) != pinned.end());

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
    CPPUNIT_ASSERT(aliceTrustStore->getCertificateStatus(id) == dhtnet::tls::TrustStore::PermissionStatus::ALLOWED);

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
    aliceTrustStore->setCertificateStatus(account.second, dhtnet::tls::TrustStore::PermissionStatus::ALLOWED);
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
    CPPUNIT_ASSERT(std::find_if(pinned.begin(), pinned.end(), [&](auto v) { return v == id; }) == pinned.end());

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
    auto devicePartialCert = std::make_shared<dht::crypto::Certificate>(device.second->toString(false));

    aliceCertStore->pinCertificate(caCert);
    aliceCertStore->pinCertificate(accountCert);
    aliceCertStore->pinCertificate(devicePartialCert);

    auto fullCert = aliceCertStore->getCertificate(device.second->getId().toString());
    CPPUNIT_ASSERT(fullCert->issuer && fullCert->issuer->getUID() == accountCert->getUID());
    CPPUNIT_ASSERT(fullCert->issuer->issuer && fullCert->issuer->issuer->getUID() == caCert->getUID());
}

void
CertStoreTest::testBannedParent()
{
    auto ca = dht::crypto::generateIdentity("test CA");
    auto account = dht::crypto::generateIdentity("test account", ca, 4096, true);
    auto device = dht::crypto::generateIdentity("test device", account);
    auto device2 = dht::crypto::generateIdentity("test device 2", account);
    auto id = ca.second->getId().toString();
    auto pinned = aliceCertStore->getPinnedCertificates();
    CPPUNIT_ASSERT(std::find_if(pinned.begin(), pinned.end(), [&](auto v) { return v == id; }) == pinned.end());

    // Ban account
    aliceTrustStore->setCertificateStatus(account.second, dhtnet::tls::TrustStore::PermissionStatus::BANNED);
    CPPUNIT_ASSERT(aliceTrustStore->getCertificateStatus(account.second->getId().toString())
                   == dhtnet::tls::TrustStore::PermissionStatus::BANNED);
    CPPUNIT_ASSERT(not aliceTrustStore->isAllowed(*account.second));
    CPPUNIT_ASSERT(not aliceTrustStore->isAllowed(*device2.second));
    CPPUNIT_ASSERT(not aliceTrustStore->isAllowed(*device.second));
}

namespace {

std::shared_ptr<dht::crypto::RevocationList>
makeCrl(const dht::crypto::Identity& ca, const dht::crypto::Certificate& revoked, uint64_t number)
{
    auto crl = std::make_shared<dht::crypto::RevocationList>();
    crl->revoke(revoked);
    crl->sign(ca, {}, number);
    return crl;
}

std::vector<std::filesystem::path>
crlFiles(const std::string& id)
{
    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(std::filesystem::path("aliceCertStore") / "crls" / id,
                                                                ec))
        files.emplace_back(entry.path());
    return files;
}

} // namespace

void
CertStoreTest::testRevocationListStorage()
{
    auto ca = dht::crypto::generateIdentity("test CA");
    auto account = dht::crypto::generateIdentity("test account", ca, 4096, true);
    auto device = dht::crypto::generateIdentity("test device", account);
    auto id = account.second->getId().toString();

    CPPUNIT_ASSERT(aliceCertStore->getRevocationLists(id).empty());

    auto crl = makeCrl(account, *device.second, 1 << 24);
    aliceCertStore->pinRevocationList(id, crl);

    auto stored = aliceCertStore->getRevocationLists(id);
    CPPUNIT_ASSERT_EQUAL(size_t(1), stored.size());
    CPPUNIT_ASSERT(stored[0]->getPacked() == crl->getPacked());
    CPPUNIT_ASSERT(stored[0]->isRevoked(*device.second));

    // Pinning the same list again is idempotent.
    aliceCertStore->pinRevocationList(id, crl);
    CPPUNIT_ASSERT_EQUAL(size_t(1), aliceCertStore->getRevocationLists(id).size());
    CPPUNIT_ASSERT_EQUAL(size_t(1), crlFiles(id).size());

    // A stored list is loaded back onto a certificate.
    auto cert = dht::crypto::Certificate(account.second->toString(false));
    aliceCertStore->loadRevocations(cert);
    CPPUNIT_ASSERT_EQUAL(size_t(1), cert.getRevocationLists().size());
}

void
CertStoreTest::testRevocationListNumberCollision()
{
    // Two devices sharing the same authority may branch from the same revocation list
    // and issue different lists carrying the same CRL number. Neither may be lost.
    auto ca = dht::crypto::generateIdentity("test CA");
    auto account = dht::crypto::generateIdentity("test account", ca, 4096, true);
    auto device1 = dht::crypto::generateIdentity("test device 1", account);
    auto device2 = dht::crypto::generateIdentity("test device 2", account);
    auto id = account.second->getId().toString();

    constexpr uint64_t sameNumber = 0x2a << 24;
    auto crl1 = makeCrl(account, *device1.second, sameNumber);
    auto crl2 = makeCrl(account, *device2.second, sameNumber);
    CPPUNIT_ASSERT(crl1->getNumber() == crl2->getNumber());
    CPPUNIT_ASSERT(crl1->getPacked() != crl2->getPacked());

    aliceCertStore->pinRevocationList(id, crl1);
    aliceCertStore->pinRevocationList(id, crl2);

    CPPUNIT_ASSERT_EQUAL(size_t(2), crlFiles(id).size());
    auto stored = aliceCertStore->getRevocationLists(id);
    CPPUNIT_ASSERT_EQUAL(size_t(2), stored.size());

    bool revokes1 = false, revokes2 = false;
    for (const auto& crl : stored) {
        revokes1 |= crl->isRevoked(*device1.second);
        revokes2 |= crl->isRevoked(*device2.second);
    }
    CPPUNIT_ASSERT(revokes1);
    CPPUNIT_ASSERT(revokes2);
}

void
CertStoreTest::testUnpinRevocationList()
{
    auto ca = dht::crypto::generateIdentity("test CA");
    auto account = dht::crypto::generateIdentity("test account", ca, 4096, true);
    auto device1 = dht::crypto::generateIdentity("test device 1", account);
    auto device2 = dht::crypto::generateIdentity("test device 2", account);
    auto id = account.second->getId().toString();

    auto crl1 = makeCrl(account, *device1.second, 1 << 24);
    auto crl2 = makeCrl(account, *device2.second, 2 << 24);
    aliceCertStore->pinRevocationList(id, crl1);
    aliceCertStore->pinRevocationList(id, crl2);
    CPPUNIT_ASSERT_EQUAL(size_t(2), aliceCertStore->getRevocationLists(id).size());

    aliceCertStore->unpinRevocationList(id, *crl1);
    auto stored = aliceCertStore->getRevocationLists(id);
    CPPUNIT_ASSERT_EQUAL(size_t(1), stored.size());
    CPPUNIT_ASSERT(stored[0]->getPacked() == crl2->getPacked());

    // Removing a list that is not stored is a no-op.
    aliceCertStore->unpinRevocationList(id, *crl1);
    CPPUNIT_ASSERT_EQUAL(size_t(1), aliceCertStore->getRevocationLists(id).size());

    aliceCertStore->unpinRevocationList(id, *crl2);
    CPPUNIT_ASSERT(aliceCertStore->getRevocationLists(id).empty());

    // Removing from an unknown certificate is a no-op.
    aliceCertStore->unpinRevocationList("nonexistent", *crl1);
}

void
CertStoreTest::testLegacyRevocationListStorage()
{
    // Lists pinned by an earlier version are named after their CRL number. They must
    // still be loaded, and be removable.
    auto ca = dht::crypto::generateIdentity("test CA");
    auto account = dht::crypto::generateIdentity("test account", ca, 4096, true);
    auto device = dht::crypto::generateIdentity("test device", account);
    auto id = account.second->getId().toString();

    auto crl = makeCrl(account, *device.second, 7 << 24);
    auto dir = std::filesystem::path("aliceCertStore") / "crls" / id;
    std::filesystem::create_directories(dir);
    fileutils::saveFile(dir / dht::toHex(crl->getNumber()), crl->getPacked());

    auto stored = aliceCertStore->getRevocationLists(id);
    CPPUNIT_ASSERT_EQUAL(size_t(1), stored.size());
    CPPUNIT_ASSERT(stored[0]->getPacked() == crl->getPacked());

    // Re-pinning it stores it under its digest; both copies hold the same list so only
    // one is reported.
    aliceCertStore->pinRevocationList(id, crl);
    CPPUNIT_ASSERT_EQUAL(size_t(2), crlFiles(id).size());
    CPPUNIT_ASSERT_EQUAL(size_t(1), aliceCertStore->getRevocationLists(id).size());

    // Removal is content-matched, so both files go away.
    aliceCertStore->unpinRevocationList(id, *crl);
    CPPUNIT_ASSERT(crlFiles(id).empty());
    CPPUNIT_ASSERT(aliceCertStore->getRevocationLists(id).empty());
}

} // namespace test
} // namespace dhtnet

JAMI_TEST_RUNNER(dhtnet::test::CertStoreTest::name());
