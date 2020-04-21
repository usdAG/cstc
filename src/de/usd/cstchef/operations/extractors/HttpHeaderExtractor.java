package de.usd.cstchef.operations.extractors;

import org.bouncycastle.util.Arrays;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "HTTP header", category = OperationCategory.EXTRACTORS, description = "Extracts a header of a HTTP request.")
public class HttpHeaderExtractor extends Operation {

	private VariableTextField headerNameField;

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		
		byte[] headerName = headerNameField.getBytes();
		if( headerName.length == 0 )
			return input;
		
		byte[] headerSearch = new byte[headerName.length + 4];
		System.arraycopy("\r\n".getBytes(), 0, headerSearch, 0, 2);
		System.arraycopy(headerName, 0, headerSearch, 2, headerName.length);
		System.arraycopy(": ".getBytes(), 0, headerSearch, headerName.length + 2, 2);
		
		IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
		IExtensionHelpers helpers = callbacks.getHelpers();
		int length = input.length;
		
		int offset = helpers.indexOf(input, headerSearch, true, 0, length);
		
		if( offset < 0 )
			throw new IllegalArgumentException("Header not found.");
		
		int valueStart = helpers.indexOf(input, " ".getBytes(), false, offset, length);
		if( valueStart < 0 )
			throw new IllegalArgumentException("Invalid Header format.");
		int valueEnd = helpers.indexOf(input, "\r\n".getBytes(), false, valueStart, length);
		if( valueEnd < 0 )
			throw new IllegalArgumentException("Invalid Header format.");
		
		byte[] result = Arrays.copyOfRange(input, valueStart + 1, valueEnd);
		return result;
	}

	@Override
	public void createUI() {
		this.headerNameField = new VariableTextField();
		this.addUIElement("Name", this.headerNameField);
	}
	
}
