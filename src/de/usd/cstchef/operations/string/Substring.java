package de.usd.cstchef.operations.string;

import javax.swing.JSpinner;

import org.bouncycastle.util.Arrays;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Substring", category = OperationCategory.STRING, description = "Extracts a substring.")
public class Substring extends Operation {

	private JSpinner startSpinner;
	private JSpinner endSpinner;

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		
		int start = (int) startSpinner.getValue();
		int end = (int) endSpinner.getValue();
		
		if( start < 0 ) 
			start = input.length + start;
		if( end < 0 )
			end = input.length + end;
		if( end > input.length )
			end = input.length + 1;
		
		byte[] slice = Arrays.copyOfRange(input, start, end);
		return slice;
	}

	@Override
	public void createUI() {
		this.startSpinner = new JSpinner();
		this.addUIElement("Start", this.startSpinner);

		this.endSpinner = new JSpinner();
		this.addUIElement("End", this.endSpinner);
	}

}
