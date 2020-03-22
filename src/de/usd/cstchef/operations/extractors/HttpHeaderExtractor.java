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

	private VariableTextField headerTxt;

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		
		try {
			
			String headerName = "\r\n" + headerTxt.getText() + ":";
			IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
			IExtensionHelpers helpers = callbacks.getHelpers();
			
			int nameStart = helpers.indexOf(input, headerName.getBytes(), true, 0, input.length);
			
			if( nameStart < 0 )
				throw new HeaderNotFoundException("Header not found.");
			
			int valueStart = helpers.indexOf(input, " ".getBytes(), false, nameStart, input.length);
			int valueEnd = helpers.indexOf(input, "\r\n".getBytes(), false, valueStart, input.length);
			
			if( valueStart < 0 || valueEnd < 0)
				throw new HeaderInvalidFormat("Invalid Header format.");
			
			byte[] result = Arrays.copyOfRange(input, valueStart + 1, valueEnd);
			return result;
			
		} catch(HeaderInvalidFormat e) {
			throw new IllegalArgumentException("Invalid Header format.");
		} catch( HeaderNotFoundException e ) {
			throw new IllegalArgumentException("Header not found.");
		} catch (Exception e) {
			throw new IllegalArgumentException("Provided input is not a valid http request.");
		}
	}

	@Override
	public void createUI() {
		this.headerTxt = new VariableTextField();
		this.addUIElement("Name", this.headerTxt);
	}
	
	class HeaderNotFoundException extends Exception {
	      public HeaderNotFoundException(String message) {
	         super(message);
	      }
	 }
	
	class HeaderInvalidFormat extends Exception {
	      public HeaderInvalidFormat(String message) {
	         super(message);
	      }
	 }
}
