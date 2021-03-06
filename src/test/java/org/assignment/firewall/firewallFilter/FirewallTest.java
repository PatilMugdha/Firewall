package org.assignment.firewall.firewallFilter;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * This test file contains different scenarios and corner cases to accept or
 * reject a packet.
 * 
 * @author patil
 *
 */
public class FirewallTest {

	private Firewall fw;
	private static long start;
	private static long end;
	private static int counter = 0;

	@BeforeClass
	public static void setStartTime() {
		start = System.currentTimeMillis();
	}

	@Before
	public void setup() {
		counter++;
		fw = new Firewall("HalfKRules.csv");
	}

	@Test
	public void testBlockPacket() {
		// such a rule is not present in the file
		assertFalse(fw.accept_packet("outbound", "udp", 50843, "255.255.255.255"));
	}

	@Test
	public void testAllowPacketExactMatch() {
		// rule is allowed: inbound,tcp,80,192.168.1.2

		assertTrue(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"));
	}

	@Test
	public void testAllowPacketWithinIPRange() {
		// rule is allowed: outbound,tcp,10000-20000,192.168.10.10-192.168.10.12

		assertTrue(fw.accept_packet("outbound", "tcp", 10000, "192.168.10.11"));
	}

	@Test
	public void testAllowPacketWithinPortRange() {
		// rule is allowed: outbound,tcp,10000-20000,192.168.10.10-192.168.10.12

		assertTrue(fw.accept_packet("outbound", "tcp", 11000, "192.168.10.12"));
	}

	@Test
	public void testBlockPacketInvalidPort() {
		// rule allowed: outbound,tcp,0-65534,0.0.0.0-255.255.255.255

		assertFalse(fw.accept_packet("outbound", "tcp", 65535, "255.255.255.255"));
	}

	@Test
	public void testBlockPacketInvalidDirection() {
		// rule is allowed: outbound,tcp,0-65534,0.0.0.0-255.255.255.255

		assertFalse(fw.accept_packet("inbound", "tcp", 65534, "255.255.255.255"));
	}

	@Test
	public void testBlockPacketInvalidProtocol() {
		// rule is allowed: outbound,tcp,0-65534,0.0.0.0-255.255.255.255

		assertFalse(fw.accept_packet("inbound", "udp", 65534, "255.255.255.255"));
	}

	@AfterClass
	public static void trackFinishTime() {
		end = System.currentTimeMillis();
		System.out.println(
				"Total time taken to run " + counter + " tests: " + (float) ((end - start) / 1000) + " seconds");
	}
}
