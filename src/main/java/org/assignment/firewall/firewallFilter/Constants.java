package org.assignment.firewall.firewallFilter;

/**
 * List of constants used. Constants are package-private.
 * 
 * @author patil
 *
 */
public class Constants {

	static final String DOT_ESCAPED = "\\.";
	static final int MAX_POWER = 3;
	static final String COMMA = ",";
	static final char COMMA_CHAR = ',';
	static final int NUMBER_ROWS = 500000 * 2;
	static final String INITIAL_IP = "0.0.0.0";
	static final String DASH = "-";
	static final String INBOUND = "inbound";
	static final String OUTBOUND = "outbound";
	static final String TCP = "tcp";
	static final String UDP = "udp";
	static final int MAX_PORT_VALUE = 65535;
	static final int MIN_PORT_VALUE = 0;
	static final int MIN_IP_VALUE = 0;
	static final int MAX_IP_VALUE = 255;
	static final String DOT = ".";
	static final String ENCODING = "UTF-8";
	static final String PORT_PATTERN =
			"^([0-9]{1,4}|[1-5][0-9]{4}|" +
			"6[0-4][0-9]{3}|65[0-4][0-9]{2}|" +
			"655[0-2][0-9]|6553[0-5])$";
	
    static final String IP_PATTERN = 
		"^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
		"([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
		"([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
		"([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";
}
