package de.usd.cstchef.operations.extractors;

import java.util.Arrays;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "HTTP Body", category = OperationCategory.EXTRACTORS, description = "Extracts the body of a HTTP request.")
public class HttpBodyExtractor extends Operation {

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		try {
			IBurpExtenderCallbacks cbs = BurpUtils.getInstance().getCallbacks();
			IRequestInfo requestInfo = cbs.getHelpers().analyzeRequest(input);
			int bodyOffset = requestInfo.getBodyOffset();

			byte[] body = Arrays.copyOfRange(input, bodyOffset, input.length);
			return body;
		} catch (Exception e) {
			throw new IllegalArgumentException("Provided input is not a valid http request.");
		}
	}
}