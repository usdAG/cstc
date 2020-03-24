package de.usd.cstchef.operations.setter;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IParameter;
import burp.IRequestInfo;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP POST Param", category = OperationCategory.SETTER, description = "Set a POST parameter to the specified value.")
public class PostSetter extends SetterOperation {

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
		
		IParameter param = getParameter(input, parameterName, IParameter.PARAM_BODY, helpers);
		
		if( !addIfNotPresent() && param == null )
			return input;
		
		if( param == null ) {
			param = helpers.buildParameter(parameterName, "dummy", IParameter.PARAM_BODY);
			input = helpers.addParameter(input, param);
			param = getParameter(input, parameterName, IParameter.PARAM_BODY, helpers);
			if( param == null )
				// This case occurs when the HTTP request is a JSON or XML request. Burp does not
				// support adding parameters to these and therefore the request should stay unmodified.
				throw new IllegalArgumentException("Failure while adding the parameter. Operation cannot be used on XML or JSON.");
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
	
	// This is required because Burps getRequestParameter returns always the first occurrence of the parameter name.
	// If you have e.g. a cookie with the same name as the POST parameter, you have no chance of getting the POST
	// parameter using getRequestParameter (at least I do not know how). 
	private IParameter getParameter(byte[] request, String paramName, byte type, IExtensionHelpers helpers) {
		
		IRequestInfo info = helpers.analyzeRequest(request);
		List<IParameter> parameters = info.getParameters();
		IParameter param = null;
		
		for(IParameter p:parameters) {
			if( p.getName().equals(paramName) )
				if( p.getType() == type ) {
					param = p;
					break;
				}
		}
		return param;
	}
}
