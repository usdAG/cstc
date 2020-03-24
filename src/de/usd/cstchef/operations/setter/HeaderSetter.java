package de.usd.cstchef.operations.setter;

import java.util.Arrays;

import javax.swing.JCheckBox;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IRequestInfo;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP Header", category = OperationCategory.SETTER, description = "Set a HTTP header to the specified value.")
public class HeaderSetter extends SetterOperation {
	
	private JCheckBox addIfNotPresent;
	
	@Override
	protected byte[] perform(byte[] input) throws Exception {
		
		byte[] newValue = getWhatBytes();
		byte[] headerName = getWhereBytes();
		if( headerName.length == 0 )
			return input;
			
		IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
		IExtensionHelpers helpers = callbacks.getHelpers();
		int length = input.length;
		
		byte[] headerSearch = new byte[headerName.length + 2];
		System.arraycopy(headerName, 0, headerSearch, 0, headerName.length);
		System.arraycopy(": ".getBytes(), 0, headerSearch, headerName.length, 2);
		
		try {
			
			int offset = helpers.indexOf(input, headerSearch, false, 0, length);
			int start = helpers.indexOf(input, ": ".getBytes(), false, offset, length) + 2;
			int end = helpers.indexOf(input, "\r\n".getBytes(), false, start, length);
			return insertAtOffset(input, start, end, newValue);
			
		} catch( IllegalArgumentException e ) {
			
			if( !addIfNotPresent.isSelected() )
				return input;

			IRequestInfo info = helpers.analyzeRequest(input);
			int bodyOffset = info.getBodyOffset() - 2;
			
			byte[] value = new byte[headerSearch.length + newValue.length + 2];
			System.arraycopy(headerSearch, 0, value, 0, headerSearch.length);
			System.arraycopy(newValue, 0, value, headerName.length + 2, newValue.length);
			System.arraycopy("\r\n".getBytes(), 0, value, headerName.length + 2 + newValue.length, 2);
			return insertAtOffset(input, bodyOffset, bodyOffset, value);
			
		}
	}
	
	@Override
	public void createUI() {
		super.createUI();
		this.addIfNotPresent = new JCheckBox("Add if not present");
	    this.addIfNotPresent.setSelected(true);
		this.addUIElement(null, this.addIfNotPresent);
	}
	
	private byte[] insertAtOffset(byte[] input, int start, int end, byte[] newValue) {
		byte[] prefix = Arrays.copyOfRange(input, 0, start);
		byte[] rest = Arrays.copyOfRange(input, end, input.length);
		
		byte[] output = new byte[prefix.length + newValue.length + rest.length];
		System.arraycopy(prefix, 0, output, 0, prefix.length);
		System.arraycopy(newValue, 0, output, prefix.length, newValue.length);
		System.arraycopy(rest, 0, output, prefix.length + newValue.length, rest.length);
		
		return output;
	}
}
