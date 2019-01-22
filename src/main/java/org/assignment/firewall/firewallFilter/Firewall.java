package org.assignment.firewall.firewallFilter;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Scanner;

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
	public boolean accept_packet(String inputDirection, String inputProtocol, int inputPort, String inputIPRange) {

		this.direction = inputDirection;
		this.protocol = inputProtocol;
		this.ip = inputIPRange;
		this.port = inputPort;
		return isPacketAllowed();
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
	 * @param args Send filePath of the firewall rules. e.g: > Firewall.java
	 *             rules.csv
	 */
	public static void main(String[] args) {
		Firewall fw = new Firewall(args[0]);
		System.out.println("Result: " + fw.accept_packet("outbound", "udp", 50843, "255.255.255.255"));
	}

}
