package de.usd.cstchef.operations.setter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;

import burp.IExtensionHelpers;
import burp.IParameter;
import burp.IRequestInfo;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.view.ui.VariableTextField;

public abstract class SetterOperation extends Operation {
	
	private VariableTextField whereToSet;
	private VariableTextField whatToSet;
	
	@Override
	public void createUI() {
		this.whereToSet = new VariableTextField();
		this.whatToSet = new VariableTextField();
		this.addUIElement("Parameter name", this.whereToSet);
		this.addUIElement("Parameter value", this.whatToSet);
	}
	
	protected String getWhere() {
		return whereToSet.getText();
	}
	
	protected byte[] getWhereBytes() {
		return whereToSet.getBytes();
	}
	
	protected String getWhat() {
		return whatToSet.getText();
	}

	protected byte[] getWhatBytes() {
		return whatToSet.getBytes();
	}
	
	// This is required because Burps getRequestParameter returns always the first occurrence of the parameter name.
	// If you have e.g. a cookie with the same name as the POST parameter, you have no chance of getting the POST
	// parameter using getRequestParameter (at least I do not know how). 
	protected IParameter getParameter(byte[] request, String paramName, byte type, IExtensionHelpers helpers) {
		
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
	
	protected byte[] urlEncode(byte[] input, boolean all, IExtensionHelpers helpers) throws IOException {
		
		byte[] newValue = input;
		
		if( all ) {
			byte[] delimiter = "%".getBytes();
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			out.write(delimiter);
			
			for (int i = 0; i < newValue.length - 1; i++) {
				out.write(Hex.encode(new byte[] { newValue[i] }));
				out.write(delimiter);
			}
			
			out.write(Hex.encode(new byte[] { newValue[newValue.length - 1] }));
			newValue = out.toByteArray();
			
		} else {
			newValue = helpers.urlEncode(input);
		}
		
		return newValue;
	}
	
	protected byte[] replaceParam(byte[] request, IParameter param, byte[] newValue) {
		
		int length = request.length;
		int start = param.getValueStart();
		int end = param.getValueEnd();
		
		byte[] prefix = Arrays.copyOfRange(request, 0, start);
		byte[] rest = Arrays.copyOfRange(request, end, length);
		
		byte[] newRequest = new byte[prefix.length + newValue.length + rest.length];
		System.arraycopy(prefix, 0, newRequest, 0, prefix.length);
		System.arraycopy(newValue, 0, newRequest, prefix.length, newValue.length);
		System.arraycopy(rest, 0, newRequest, prefix.length + newValue.length, rest.length);
		
		return newRequest;
	}
}
