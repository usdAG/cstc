package de.usd.cstchef.operations.string;

import javax.swing.JSpinner;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Substring", category = OperationCategory.STRING, description = "Extracts a substring.")
public class Substring extends Operation {

	private JSpinner startSpinner;
	private JSpinner endSpinner;

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		String inputStr = new String(input);
		int start = (int) startSpinner.getValue();
		int end = (int) endSpinner.getValue();

		return inputStr.substring(start, end).getBytes();
	}

	@Override
	public void createUI() {
		this.startSpinner = new JSpinner();
		this.addUIElement("Start", this.startSpinner);

		this.endSpinner = new JSpinner();
		this.addUIElement("End", this.endSpinner);
	}

}