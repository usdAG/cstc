package de.usd.cstchef.operations.setter;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "HTTP GET Setter", category = OperationCategory.SETTER, description = "Sets the given variable on the given Key.")
public class GetSetter extends SetterOperation {

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		//TODO this has some issues.
		
		String httpRequest = new String(input);
		if (!getWhere().equals("")) {
			return httpRequest.replaceFirst(getWhere() + "=[^(&|\\s)]*", getWhere() + "=" + getWhat()).getBytes();
		}
		else {
			return input;
		}
	}
}
