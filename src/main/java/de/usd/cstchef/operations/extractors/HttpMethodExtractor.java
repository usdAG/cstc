package de.usd.cstchef.operations.extractors;

import org.bouncycastle.util.Arrays;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP Method", category = OperationCategory.EXTRACTORS, description = "Extracts the method of a HTTP request.")
public class HttpMethodExtractor extends Operation {

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		try {
			IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
			IExtensionHelpers helpers = callbacks.getHelpers();
			int length = input.length;
			
			int methodEnd = helpers.indexOf(input, " ".getBytes(), false, 0, length);
			byte[] result = Arrays.copyOfRange(input, 0, methodEnd);
			
			return result;
			
		} catch (Exception e) {
			throw new IllegalArgumentException("Provided input is not a valid http request.");
		}
	}
}
