package de.usd.cstchef.operations.string;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Lowercase", category = OperationCategory.STRING, description = "Change string to lowercase.")
public class Lowercase extends Operation {

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		try {
			if(input != null) {
				String inputStr = new String(input);
				return inputStr.toLowerCase().getBytes();	
			}
			else {
				return "".getBytes();
			}
			 
		} catch (Exception e) {
			return input;
		}
	}	
}
