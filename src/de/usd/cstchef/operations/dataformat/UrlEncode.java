package de.usd.cstchef.operations.dataformat;

import java.net.URLEncoder;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Url encode", category = OperationCategory.DATAFORMAT, description = "Url encode")
public class UrlEncode extends Operation {

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		String result = URLEncoder.encode(new String(input), "UTF-8");
		return result.getBytes();
	}

}
