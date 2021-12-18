package de.usd.cstchef.operations.string;

import org.bouncycastle.util.Arrays;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Reverse", category = OperationCategory.STRING, description = "Returns the reversed input.")
public class Reverse extends Operation {

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		return Arrays.reverse(input);
	}

}