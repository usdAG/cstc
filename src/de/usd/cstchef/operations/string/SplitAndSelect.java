package de.usd.cstchef.operations.string;

import org.bouncycastle.util.Arrays;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "Split and Select", category = OperationCategory.STRING, description = "Split input and select one item.")
public class SplitAndSelect extends Operation {

	private VariableTextField item;
	private VariableTextField delim;

	@Override
	protected byte[] perform(byte[] input) throws Exception {

		byte[] delimmiter = delim.getBytes();

		int itemNumber = 0;
		try {
			String itemValue = item.getText();
			itemNumber = Integer.valueOf(itemValue);
		} catch(Exception e) {
			return input;
		}

		if( itemNumber < 0 )
			return input;

		IBurpExtenderCallbacks cbs = BurpUtils.getInstance().getCallbacks();
		IExtensionHelpers helpers = cbs.getHelpers();
		int length = input.length;

		int start = 0;
		int offset = 0;
		int counter = 0;
		while( counter < itemNumber ) {
			offset = helpers.indexOf(input, delimmiter, false, start, length);
			if( offset >= 0 ) {
				start = offset + delimmiter.length;
				counter++;
			} else {
				break;
			}
		}

		int end = helpers.indexOf(input, delimmiter, false, start, length);
		if( end < 0 )
			end = length;

		byte[] result = Arrays.copyOfRange(input, start, end);
		return result;
	}

	@Override
	public void createUI() {
		this.delim = new VariableTextField();
		this.addUIElement("Delimmiter", this.delim);
		this.item = new VariableTextField();
		this.addUIElement("Item number", this.item);
	}
}
