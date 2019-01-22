package org.assignment.firewall.firewallFilter;

/**
 * This class includes all the parsing and filter operations applied on
 * different fields in the csv file and in input
 * 
 * @author patil
 *
 */
public class FilterOperations {

	/**
	 * checks inputs against fields which contain values from every line in .csv
	 * file.
	 * 
	 * @param fields
	 * @param inputDirection
	 * @param inputProtocol
	 * @param inputIP
	 * @param inputPort
	 * @return boolean result
	 */
	static boolean filter(String[] fields, String inputDirection, String inputProtocol, String inputIP,
			long inputPort) {
		long[] portRange = convertPorts(fields[2]);
		long[] ipRange = getIPsToIntegerArray(fields[3]);

		return fields[0].equals(inputDirection) && fields[1].equals(inputProtocol)
				&& liesWithinIPRange(ipRange, inputIP) && liesWithinPortRange(portRange, inputPort);
	}

	/**
	 * checks whether input IP falls within range
	 * 
	 * @param ipRange
	 * @param inputIP
	 * @return true/false
	 */
	private static boolean liesWithinIPRange(long[] ipRange, String inputIP) {
		long testIP = convertIpToInteger(inputIP);
		if (ipRange[1] == 0)
			return testIP == ipRange[0];
		return testIP >= ipRange[0] && testIP <= ipRange[1];
	}

	/**
	 * checks whether input port falls within range
	 * 
	 * @param portRange
	 * @param port
	 * @return true/false
	 */
	private static boolean liesWithinPortRange(long[] portRange, long port) {
		if (portRange[1] == 0)
			return port == portRange[0];
		return port >= portRange[0] && port <= portRange[1];
	}

	/**
	 * This will parse IP range and put individual IP inside array
	 * 
	 * @param ipRange which is a string containing IPs e.g: 0.0.0.0-147.59.153.15
	 * @return array of IPs
	 */
	private static long[] getIPsToIntegerArray(String ipRange) {
		String[] strIPs = ipRange.split(Constants.DASH);
		int i = 0;
		long[] ips = new long[2];
		for (String ip : strIPs) {
			ips[i++] = convertIpToInteger(ip);
		}
		return ips;
	}

	/**
	 * converts IP octets to long value representing whole IP address.
	 * 
	 * @param ip
	 * @return long value of IP address
	 */
	public static long convertIpToInteger(String ip) {

		String[] octets = ip.split(Constants.DOT_ESCAPED);

		int power = Constants.MAX_POWER;
		long total = 0;
		for (String octet : octets) {
			Integer value = Integer.parseInt(octet);
			total += value * Math.pow(256, power--);
		}
		return total;
	}

	/**
	 * parse and store ports in an array
	 * 
	 * @param portRange which is string containing ports. e.g: 0-65535
	 * @return array
	 */
	private static long[] convertPorts(String portRange) {
		String[] strPorts = portRange.split(Constants.DASH);
		long[] ports = new long[2];

		int i = 0;
		for (String port : strPorts) {
			ports[i++] = Long.valueOf(port);
		}
		return ports;
	}
}
