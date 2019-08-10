package de.usd.cstchef.operations.arithmetic;

import javax.swing.JCheckBox;
import javax.swing.JTextField;

import de.usd.cstchef.operations.Operation;

public abstract class ArithmeticOperation extends Operation {

	private JTextField numberInput;
	private JCheckBox floatCheckBox;

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		String i = new String(input);
		
		//A little trick
		if (i.isEmpty()) {
			i = "0";
		}
		
		Double input_number = Double.valueOf(i);
		Double static_number = Double.valueOf(numberInput.getText());
		Double result_number = calculate(input_number, static_number);
		
		String result = "";
		if (this.floatCheckBox.isSelected()) {
			result = String.valueOf(result_number);
		}
		else {
			result = String.valueOf(Math.round(result_number));
		}
		
		return result.getBytes();		
	}

	protected abstract double calculate(double input_number, double static_number);

	@Override
	public void createUI() {
		this.numberInput = new JTextField("1");
		this.addUIElement("Number", this.numberInput);
		
		this.floatCheckBox = new JCheckBox();
		this.addUIElement("Point Number", this.floatCheckBox);
	}

}
