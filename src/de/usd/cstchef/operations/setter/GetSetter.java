package de.usd.cstchef.operations.setter;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IParameter;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP Set GET Parameter", category = OperationCategory.SETTER, description = "Sets the given variable on the given Key.")
public class GetSetter extends SetterOperation {

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		
		String parameterName = getWhere();
		if( parameterName.equals("") )
			return input;
			
		IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
		IExtensionHelpers helpers = callbacks.getHelpers();
		
		byte[] newValue = getWhatBytes();
	
		if( urlEncodeAll() ) {
			byte[] delimiter = "%".getBytes();
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			out.write(delimiter);
			
			for (int i = 0; i < newValue.length - 1; i++) {
				out.write(Hex.encode(new byte[] { newValue[i] }));
				out.write(delimiter);
			}
			
			out.write(Hex.encode(new byte[] { newValue[newValue.length - 1] }));
			newValue = out.toByteArray();
			
		} else if( urlEncode() ) {
			newValue = helpers.urlEncode(getWhatBytes());
		}
		
		IParameter param = helpers.getRequestParameter(input, parameterName);
		if( param == null || param.getType() != IParameter.PARAM_URL ) {
			param = helpers.buildParameter(parameterName, "dummy", IParameter.PARAM_URL);
			input = helpers.addParameter(input, param);
			param = helpers.getRequestParameter(input, parameterName);
		}

		int length = input.length;
		int start = param.getValueStart();
		int end = param.getValueEnd();
		
		byte[] prefix = Arrays.copyOfRange(input, 0, start);
		byte[] rest = Arrays.copyOfRange(input, end, length);
		
		byte[] newRequest = new byte[prefix.length + newValue.length + rest.length];
		System.arraycopy(prefix, 0, newRequest, 0, prefix.length);
		System.arraycopy(newValue, 0, newRequest, prefix.length, newValue.length);
		System.arraycopy(rest, 0, newRequest, prefix.length + newValue.length, rest.length);
		
		return newRequest;
	}
}
