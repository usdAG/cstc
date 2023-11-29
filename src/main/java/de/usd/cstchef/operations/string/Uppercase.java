package de.usd.cstchef.operations.string;

import burp.BurpUtils;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Uppercase", category = OperationCategory.STRING, description = "Change string to uppercase.")
public class Uppercase extends Operation {

	@Override
	protected ByteArray perform(ByteArray input) throws Exception {
		try {
			if(input != null) {
				String inputStr = input.toString();
				return factory.createByteArray(inputStr.toUpperCase());	
			}
			else {
				return factory.createByteArray("");
			}			 
		} catch (Exception e) {
			return input;
		}
	}	
}
