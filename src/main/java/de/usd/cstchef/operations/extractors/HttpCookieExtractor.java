package de.usd.cstchef.operations.extractors;

import org.bouncycastle.util.Arrays;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IResponseInfo;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "HTTP Cookie", category = OperationCategory.EXTRACTORS, description = "Extracts a cookie from a HTTP request.")
public class HttpCookieExtractor extends Operation {

	private VariableTextField cookieNameField;

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		
		byte[] cookieName = cookieNameField.getBytes();
		if( cookieName.length == 0 )
			return input;
		
		byte[] cookieSearch = new byte[cookieName.length + 1];
		System.arraycopy(cookieName, 0, cookieSearch, 0, cookieName.length);
		System.arraycopy("=".getBytes(), 0, cookieSearch, cookieName.length, 1);
		
		IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
		IExtensionHelpers helpers = callbacks.getHelpers();
		int length = input.length;
		
		IResponseInfo resp = helpers.analyzeResponse(input);
		boolean isRequest = (resp.getStatusCode() == 0);
		
		String cookieHeader = "\r\nSet-Cookie: ";
		if(isRequest)
			cookieHeader = "\r\nCookie: ";
		
		try {
			
			int offset = helpers.indexOf(input, cookieHeader.getBytes(), false, 0, length);
			int line_end = helpers.indexOf(input, "\r\n".getBytes(), false, offset + 2, length);
			int start = helpers.indexOf(input, cookieSearch, true, offset, line_end);
			int end = helpers.indexOf(input, ";".getBytes(), true, start, line_end);
			
			if( end < 0 )
				end = line_end;
			
			return Arrays.copyOfRange(input, start + cookieName.length + 1, end);
			
		} catch( IllegalArgumentException e ) {
			throw new IllegalArgumentException("Cookie not found.");
		}
	}

	@Override
	public void createUI() {
		this.cookieNameField = new VariableTextField();
		this.addUIElement("Name", this.cookieNameField);
	}
}
