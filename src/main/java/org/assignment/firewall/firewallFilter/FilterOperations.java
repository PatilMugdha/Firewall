package org.assignment.firewall.firewallFilter;

public class FilterOperations {

	private static String DOT_ESCAPED = "\\.";
	private static String DASH = "-";
	private static int MAX_POWER = 3;

	/**
	 * checks inputs against fields which contain values from every line in .csv
	 * file
	 * 
	 * @param fields
	 * @param inputDirection
	 * @param inputProtocol
	 * @param inputIP
	 * @param inputPort
	 * @return
	 */
	static boolean filter(String[] fields, String inputDirection, String inputProtocol, String inputIP,
			double inputPort) {
		double[] portRange = convertPorts(fields[2]);
		double[] ipRange = getIPsToIntegerArray(fields[3]);

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
	private static boolean liesWithinIPRange(double[] ipRange, String inputIP) {
		double testIP = convertIpToInteger(inputIP);
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
	private static boolean liesWithinPortRange(double[] portRange, double port) {
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
	private static double[] getIPsToIntegerArray(String ipRange) {
		String[] strIPs = ipRange.split(FilterOperations.DASH);
		int i = 0;
		double[] ips = new double[2];
		for (String ip : strIPs) {
			ips[i++] = convertIpToInteger(ip);
		}
		return ips;
	}

	/**
	 * converts IP octets to double value representing whole IP address.
	 * 
	 * @param ip
	 * @return double value of IP address
	 */
	public static double convertIpToInteger(String ip) {

		String[] octets = ip.split(FilterOperations.DOT_ESCAPED);

		int power = FilterOperations.MAX_POWER;
		double total = 0;
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
	private static double[] convertPorts(String portRange) {
		String[] strPorts = portRange.split(FilterOperations.DASH);
		double[] ports = new double[2];

		int i = 0;
		for (String port : strPorts) {
			ports[i++] = Double.valueOf(port);
		}
		return ports;
	}
}
