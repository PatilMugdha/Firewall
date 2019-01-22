package org.assignment.firewall.firewallFilter;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class defines the required interfaces for accepting packet.
 * @author patil
 *
 */
public class Firewall {

	private String filePath;
	private String direction;
	private String protocol;
	private String ip;
	private int port;

	/**
	 * constructor accepts filePath
	 * 
	 * @param filePath
	 */
	public Firewall(String filePath) {
		this.filePath = filePath;
	}

	/**
	 * Interface to accept packet
	 * 
	 * @param inputDirection
	 * @param inputProtocol
	 * @param inputPort
	 * @param inputIPRange
	 * @return boolean result
	 */
	public boolean accept_packet(final String inputDirection, final String inputProtocol, final int inputPort,
			final String inputIPRange) {

		this.direction = inputDirection;
		this.protocol = inputProtocol;
		this.ip = inputIPRange;
		this.port = inputPort;
		return isPacketValid() ? isPacketAllowed() : false;
	}
    
	/**
	 * This method will validate the packet ip and port before sending
	 * for further processing.
	 * @return true/false
	 */
	private boolean isPacketValid() {
		Matcher matcher = Pattern.compile(Constants.IP_PATTERN).matcher(ip);
		boolean isIPValid = matcher.matches();
		matcher = Pattern.compile(Constants.PORT_PATTERN).matcher(String.valueOf(port));
		boolean isPortValid = matcher.matches();
		return isIPValid && isPortValid;
	}

	/**
	 * Parse and scan complete rules.csv file to check against the input packet
	 * values
	 * 
	 * @return true/false
	 */
	private boolean isPacketAllowed() {

		FileInputStream inputStream = null;
		Scanner scanner = null;
		try {
			inputStream = new FileInputStream(filePath);
			// scan and parse every line from file
			scanner = new Scanner(inputStream, Constants.ENCODING);
			while (scanner.hasNextLine()) {
				String line = scanner.nextLine();
				String[] fields = line.split(Constants.COMMA);
				// filter packet
				if (FilterOperations.filter(fields, direction, protocol, ip, port))
					return true;
			}
		} catch (FileNotFoundException e) {
			System.out.println("Input file: " + filePath + " not found with message: " + e.getMessage());

		} finally {
			if (inputStream != null) {
				try {
					inputStream.close();
				} catch (IOException e) {
					System.out.println("Exception while closing inputStream with message: " + e.getMessage());
				}
			}
			if (scanner != null) {
				scanner.close();
			}
		}
		return false;
	}

	/**
	 * 
	 * @param args Send filePath of the firewall rules. 
	 * e.g: > Firewall.java rules.csv
	 */
	public static void main(String[] args) {

		Firewall fw = new Firewall("OneMRules.csv");
		long start = System.currentTimeMillis();
		System.out.println("Result: " + fw.accept_packet("outbound", "udp", 50843, "255.255.255.255"));
		long end = System.currentTimeMillis();
		System.out.println("Time taken to filter packet using 1M rules: " + (end - start) + " ms");
	}

}
