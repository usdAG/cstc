package de.usd.cstchef.operations.string;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Lowercase", category = OperationCategory.STRING, description = "Change string to lowercase.")
public class Lowercase extends Operation {

	@Override
	protected ByteArray perform(ByteArray input) throws Exception {
		try {
			if(input != null) {
				String inputStr = input.toString();
				return factory.createByteArray(inputStr.toLowerCase());	
			}
			else {
				return factory.createByteArray("");
			}
			 
		} catch (Exception e) {
			return input;
		}
	}	
}
