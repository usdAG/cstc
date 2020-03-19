package de.usd.cstchef.operations.setter;

import java.util.Arrays;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IParameter;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "HTTP Set GET Parameter", category = OperationCategory.SETTER, description = "Sets the given variable on the given Key.")
public class GetSetter extends SetterOperation {

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		//TODO this has some issues.
		
		String parameterName = getWhere();
		
		if (!parameterName.equals("")) {
			
			IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
			IExtensionHelpers helpers = callbacks.getHelpers();
			int length = input.length;
			
			if( urlEncode() ) {
				
				//TODO: burps urlEncode seems only to encode URL special chars. Stuff like
				//      null bytes seem not to be encoded. This needs to be fixed.
				byte[] paramValue = helpers.urlEncode(getWhatBytes());
				IParameter param = helpers.buildParameter(parameterName, helpers.bytesToString(paramValue), IParameter.PARAM_URL);
				input = helpers.updateParameter(input, param);
				return input;
				
			} else {
				
				IParameter param = helpers.getRequestParameter(input, parameterName);
				if( param == null )
					return input;
				
				int start = param.getValueStart();
				int end = param.getValueEnd();
				
				byte[] prefix = Arrays.copyOfRange(input, 0, start);
				byte[] newValue = getWhatBytes();
				byte[] rest = Arrays.copyOfRange(input, end, length);
				
				byte[] newRequest = new byte[prefix.length + newValue.length + rest.length];
				System.arraycopy(prefix, 0, newRequest, 0, prefix.length);
				System.arraycopy(newValue, 0, newRequest, prefix.length, newValue.length);
				System.arraycopy(rest, 0, newRequest, prefix.length + newValue.length, rest.length);
				
				return newRequest;
			}
		}
		else {
			return input;
		}
	}
}
