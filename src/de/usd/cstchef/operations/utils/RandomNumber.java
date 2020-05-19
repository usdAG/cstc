package de.usd.cstchef.operations.utils;

import java.security.SecureRandom;

import javax.swing.JTextField;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Random Number", category = OperationCategory.UTILS, description = "Generate a random number.")
public class RandomNumber extends Operation {

	private JTextField maximum;

	@Override
	protected byte[] perform(byte[] input) throws Exception {

		SecureRandom secRand = new SecureRandom();
		try {
			int bound = Integer.valueOf(this.maximum.getText()) + 1;
			int random = Math.abs(secRand.nextInt(bound));
			return String.valueOf(random).getBytes();
		} catch( Exception e ) {
			int random = Math.abs(secRand.nextInt());
			return String.valueOf(random).getBytes();
		}
	}

	public void createUI() {
		this.maximum = new JTextField();
		this.addUIElement("Maximum Number", this.maximum);
	}

}
