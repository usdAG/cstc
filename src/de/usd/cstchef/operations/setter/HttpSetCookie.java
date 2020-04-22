package de.usd.cstchef.operations.setter;

import java.util.Arrays;

import javax.swing.JCheckBox;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IResponseInfo;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP Cookie", category = OperationCategory.SETTER, description = "Set a HTTP cookie to the specified value.")
public class HttpSetCookie extends SetterOperation {
	
	private JCheckBox addIfNotPresent;
	
	@Override
	protected byte[] perform(byte[] input) throws Exception {
		
		byte[] newValue = getWhatBytes();
		byte[] cookieName = getWhereBytes();
		if( cookieName.length == 0 )
			return input;
			
		IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
		IExtensionHelpers helpers = callbacks.getHelpers();
		int length = input.length;
		
		byte[] cookieSearch = new byte[cookieName.length + 1];
		System.arraycopy(cookieName, 0, cookieSearch, 0, cookieName.length);
		System.arraycopy("=".getBytes(), 0, cookieSearch, cookieName.length, 1);
		
		IResponseInfo resp = helpers.analyzeResponse(input);
		boolean isRequest = (resp.getStatusCode() == 0);
		
		String cookieHeader = "\r\nSet-Cookie: ";
		if(isRequest)
			cookieHeader = "\r\nCookie: ";
		
		int offset = -1;
		int cookieHeaderLength = cookieHeader.length();
		
		try {
			
			offset = helpers.indexOf(input, cookieHeader.getBytes(), false, 0, length);
			int line_end = helpers.indexOf(input, "\r\n".getBytes(), false, offset + 2, length);
			int start = helpers.indexOf(input, cookieSearch, true, offset, line_end);
			int end = helpers.indexOf(input, ";".getBytes(), true, start, line_end);
			
			if( end < 0 )
				end = line_end;
			
			return insertAtOffset(input, start + cookieSearch.length, end, newValue);
			
		} catch( IllegalArgumentException e ) {
			
			if( !addIfNotPresent.isSelected() )
				return input;
			
			if( (offset > 0) && isRequest ) {
				
				byte[] value = new byte[cookieName.length + newValue.length + 3];
				System.arraycopy(cookieName, 0, value, 0, cookieName.length);
				System.arraycopy("=".getBytes(), 0, value, cookieName.length, 1);
				System.arraycopy(newValue, 0, value, cookieName.length + 1, newValue.length);
				System.arraycopy("; ".getBytes(), 0, value, cookieName.length + 1 + newValue.length, 2);
				return insertAtOffset(input, offset + cookieHeaderLength, offset + cookieHeaderLength, value);
				
			} else {
				
				int bodyOffset = resp.getBodyOffset() - 4;
				byte[] value = new byte[cookieName.length + newValue.length + cookieHeaderLength + 2];
				System.arraycopy(cookieHeader.getBytes(), 0, value, 0, cookieHeaderLength);
				System.arraycopy(cookieName, 0, value, cookieHeaderLength, cookieName.length);
				System.arraycopy("=".getBytes(), 0, value, cookieHeaderLength + cookieName.length, 1);
				System.arraycopy(newValue, 0, value, cookieHeaderLength + cookieName.length + 1, newValue.length);
				System.arraycopy(";".getBytes(), 0, value, cookieHeaderLength + cookieName.length + 1 + newValue.length, 1);
				return insertAtOffset(input, bodyOffset, bodyOffset, value);
			}
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
