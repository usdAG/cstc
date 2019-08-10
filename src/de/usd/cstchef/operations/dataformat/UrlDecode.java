package de.usd.cstchef.operations.dataformat;

import java.net.URLDecoder;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Url decode", category = OperationCategory.DATAFORMAT, description = "Url decoding")
public class UrlDecode extends Operation {

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		String result = URLDecoder.decode(new String(input), "UTF-8");
		return result.getBytes();
	}

}
