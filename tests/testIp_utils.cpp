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

#include "ip_utils.h"
#include "test_runner.h"

namespace dhtnet {
namespace test {

class IpUtilsTest : public CppUnit::TestFixture
{
public:
    static std::string name() { return "ip_utils"; }

private:
    void link_local_test();
    void private_address_test();
    void routable_test();
    void multicast_test();

    CPPUNIT_TEST_SUITE(IpUtilsTest);
    CPPUNIT_TEST(link_local_test);
    CPPUNIT_TEST(private_address_test);
    CPPUNIT_TEST(routable_test);
    CPPUNIT_TEST(multicast_test);
    CPPUNIT_TEST_SUITE_END();
};

CPPUNIT_TEST_SUITE_NAMED_REGISTRATION(IpUtilsTest, IpUtilsTest::name());

void
IpUtilsTest::link_local_test()
{
    // IPv6 link-local: fe80::/10 covers fe80 through febf.
    CPPUNIT_ASSERT(IpAddr("fe80::7c04:f7a2:d572:1315").isLinkLocal());
    CPPUNIT_ASSERT(IpAddr("fe80::1").isLinkLocal());
    CPPUNIT_ASSERT(IpAddr("febf::1").isLinkLocal());

    // Neighbouring prefixes must not be mistaken for link-local.
    CPPUNIT_ASSERT(not IpAddr("fec0::1").isLinkLocal());
    CPPUNIT_ASSERT(not IpAddr("fd00::1").isLinkLocal());
    CPPUNIT_ASSERT(not IpAddr("2001:861:2d4d:9c0::1").isLinkLocal());
    CPPUNIT_ASSERT(not IpAddr("::1").isLinkLocal());

    // IPv4 link-local: 169.254.0.0/16.
    CPPUNIT_ASSERT(IpAddr("169.254.0.0").isLinkLocal());
    CPPUNIT_ASSERT(IpAddr("169.254.1.2").isLinkLocal());
    CPPUNIT_ASSERT(IpAddr("169.254.255.255").isLinkLocal());
    CPPUNIT_ASSERT(not IpAddr("169.253.255.255").isLinkLocal());
    CPPUNIT_ASSERT(not IpAddr("169.255.0.0").isLinkLocal());
    CPPUNIT_ASSERT(not IpAddr("192.168.1.78").isLinkLocal());
    CPPUNIT_ASSERT(not IpAddr("76.71.241.88").isLinkLocal());
}

void
IpUtilsTest::private_address_test()
{
    // Link-local addresses are never publicly routable.
    CPPUNIT_ASSERT(IpAddr("fe80::1").isPrivate());
    CPPUNIT_ASSERT(IpAddr("169.254.1.2").isPrivate());

    // Unique local addresses span fc00::/7, so both prefixes qualify.
    CPPUNIT_ASSERT(IpAddr("fc00::1").isPrivate());
    CPPUNIT_ASSERT(IpAddr("fd12:3456:789a::1").isPrivate());
    CPPUNIT_ASSERT(not IpAddr("fbff::1").isPrivate());
    CPPUNIT_ASSERT(not IpAddr("fe00::1").isPrivate());

    CPPUNIT_ASSERT(IpAddr("10.0.0.1").isPrivate());
    CPPUNIT_ASSERT(IpAddr("172.16.0.1").isPrivate());
    CPPUNIT_ASSERT(IpAddr("192.168.1.78").isPrivate());
    CPPUNIT_ASSERT(IpAddr("127.0.0.1").isPrivate());

    CPPUNIT_ASSERT(not IpAddr("76.71.241.88").isPrivate());
    CPPUNIT_ASSERT(not IpAddr("2001:861:2d4d:9c0::1").isPrivate());
}

void
IpUtilsTest::routable_test()
{
    // The address seen in the reported ICE log: a link-local address used as
    // both the local and the mapped half of a server reflexive candidate.
    CPPUNIT_ASSERT(not IpAddr("fe80::7c04:f7a2:d572:1315").isRoutable());
    CPPUNIT_ASSERT(not IpAddr("169.254.1.2").isRoutable());
    CPPUNIT_ASSERT(not IpAddr("127.0.0.1").isRoutable());
    CPPUNIT_ASSERT(not IpAddr("::1").isRoutable());
    CPPUNIT_ASSERT(not IpAddr("0.0.0.0").isRoutable());
    CPPUNIT_ASSERT(not IpAddr("::").isRoutable());
    CPPUNIT_ASSERT(not IpAddr().isRoutable());

    // A multicast address names a group, not a peer. 239.192.0.1 in
    // particular is the group used for local peer discovery.
    CPPUNIT_ASSERT(not IpAddr("224.0.0.1").isRoutable());
    CPPUNIT_ASSERT(not IpAddr("239.192.0.1").isRoutable());
    CPPUNIT_ASSERT(not IpAddr("ff02::1").isRoutable());

    // Private addresses must keep working: a published address equal to a LAN
    // address is what peer discovery yields with no Internet access.
    CPPUNIT_ASSERT(IpAddr("192.168.1.78").isRoutable());
    CPPUNIT_ASSERT(IpAddr("10.42.0.2").isRoutable());
    CPPUNIT_ASSERT(IpAddr("172.16.0.1").isRoutable());
    CPPUNIT_ASSERT(IpAddr("fd12:3456:789a::1").isRoutable());

    CPPUNIT_ASSERT(IpAddr("76.71.241.88").isRoutable());
    CPPUNIT_ASSERT(IpAddr("2001:861:2d4d:9c0::1").isRoutable());
}

void
IpUtilsTest::multicast_test()
{
    // IPv4 multicast: 224.0.0.0/4.
    CPPUNIT_ASSERT(IpAddr("224.0.0.0").isMulticast());
    CPPUNIT_ASSERT(IpAddr("224.0.0.1").isMulticast());
    CPPUNIT_ASSERT(IpAddr("239.192.0.1").isMulticast());
    CPPUNIT_ASSERT(IpAddr("239.255.255.255").isMulticast());
    CPPUNIT_ASSERT(not IpAddr("223.255.255.255").isMulticast());
    CPPUNIT_ASSERT(not IpAddr("240.0.0.0").isMulticast());

    // IPv6 multicast: ff00::/8.
    CPPUNIT_ASSERT(IpAddr("ff00::1").isMulticast());
    CPPUNIT_ASSERT(IpAddr("ff02::1").isMulticast());
    CPPUNIT_ASSERT(not IpAddr("feff::1").isMulticast());

    CPPUNIT_ASSERT(not IpAddr("192.168.1.78").isMulticast());
    CPPUNIT_ASSERT(not IpAddr("76.71.241.88").isMulticast());
    CPPUNIT_ASSERT(not IpAddr("2001:861:2d4d:9c0::1").isMulticast());
    CPPUNIT_ASSERT(not IpAddr().isMulticast());
}

} // namespace test
} // namespace dhtnet

JAMI_TEST_RUNNER(dhtnet::test::IpUtilsTest::name());
