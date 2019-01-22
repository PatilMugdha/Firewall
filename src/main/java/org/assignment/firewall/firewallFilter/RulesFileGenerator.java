package org.assignment.firewall.firewallFilter;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Random;

import com.opencsv.CSVWriter;

/**
 * This file is used to generate a csv file which has firewall rules for
 * filtering network traffic.
 * 
 * For the purpose of simplicity, only port ranges [0-<random number <=65535>]
 * and ip ranges from [0.0.0.0-255.255.255.255] are generated as part of sample
 * file generation.
 * 
 * @author patil
 *
 */
public class RulesFileGenerator {

	public static void main(String[] args) {

		RulesFileGenerator fileGenerator = new RulesFileGenerator();
		File file = new File(args[0]);
		try {
			// create FileWriter object with file as parameter
			FileWriter outputfile = new FileWriter(file);

			// create CSVWriter object filewriter object as parameter
			CSVWriter writer = new CSVWriter(outputfile, Constants.COMMA_CHAR, CSVWriter.NO_QUOTE_CHARACTER);

			String[] direction = { Constants.INBOUND, Constants.OUTBOUND };
			String[] protocol = { Constants.TCP, Constants.UDP };

			// add data to csv
			for (int i = 0; i < Constants.NUMBER_ROWS; i++) {
				String[] octetRange = { Constants.INITIAL_IP, fileGenerator.getIP() };
				String[] portRange = { "" + Constants.MIN_PORT_VALUE, fileGenerator.getPort() };
				String[] data1 = { direction[new Random().nextInt(2)], protocol[new Random().nextInt(2)],
						portRange[0] + Constants.DASH + portRange[1], octetRange[0] + Constants.DASH + octetRange[1] };
				writer.writeNext(data1);
			}

			// closing writer connection
			writer.close();
		} catch (IOException e) {
			System.out.println("Exception occured while creating test rules file with message: " + e.getMessage());
		}

	}

	/**
	 * 
	 * @return port value
	 */
	private String getPort() {
		return "" + getRandomArbitrary(Constants.MIN_PORT_VALUE, Constants.MAX_PORT_VALUE);
	}

	/**
	 * create an IP within randomly generated values range
	 * 
	 * @return well-formed IP e.g: 127.0.0.1
	 */
	private String getIP() {
		return getRandomArbitrary(Constants.MIN_IP_VALUE, Constants.MAX_IP_VALUE) + Constants.DOT
				+ getRandomArbitrary(Constants.MIN_IP_VALUE, Constants.MAX_IP_VALUE) + Constants.DOT
				+ getRandomArbitrary(Constants.MIN_IP_VALUE, Constants.MAX_IP_VALUE) + Constants.DOT
				+ getRandomArbitrary(Constants.MIN_IP_VALUE, Constants.MAX_IP_VALUE);

	}

	/**
	 * Generate random numbers within given range
	 * 
	 * @param min
	 * @param max
	 * @return random value
	 */
	public int getRandomArbitrary(int min, int max) {
		return (int) (Math.random() * (max - min) + min);
	}
}
