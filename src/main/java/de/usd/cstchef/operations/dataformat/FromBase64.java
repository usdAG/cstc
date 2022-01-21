package de.usd.cstchef.operations.dataformat;

import java.util.Base64;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "From Base64", category = OperationCategory.DATAFORMAT, description = "Decode a base64 string.")
public class FromBase64 extends Operation {

	@Override
	protected byte[] perform(byte[] input) {
		return Base64.getDecoder().decode(input);
	}
}
