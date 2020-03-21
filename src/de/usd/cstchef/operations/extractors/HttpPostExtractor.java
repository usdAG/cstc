package de.usd.cstchef.operations.extractors;

import java.util.Arrays;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IParameter;
import burp.IRequestInfo;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextArea;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "HTTP POST Parameter", category = OperationCategory.EXTRACTORS, description = "Extracts a POST parameter of a HTTP request.")
public class HttpPostExtractor extends Operation {

	protected VariableTextField parameter;

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		try {
			
			String parameterName = parameter.getText();
			IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
			IExtensionHelpers helpers = callbacks.getHelpers();

			IParameter param = helpers.getRequestParameter(input, parameterName);
			if( param == null)
				throw new ParameterNotFoundException("Parameter name not found.");
			if( param.getType() != IParameter.PARAM_BODY ) 
				throw new ParameterWrongType("Parameter type is not POST");
			
			int start = param.getValueStart();
			int end = param.getValueEnd();
			
			byte[] result = Arrays.copyOfRange(input, start, end);
			return result;
			
		} catch( ParameterNotFoundException e ) {
			throw new IllegalArgumentException("Parameter name not found.");
		} catch( ParameterWrongType e ) {
			throw new IllegalArgumentException("Parameter type is not POST");
		} catch (Exception e) {
			throw new IllegalArgumentException("Provided input is not a valid http request.");
		}
	}

	@Override
	public void createUI() {
		this.parameter = new VariableTextField();
		this.addUIElement("Parameter", this.parameter);
	}
	
	class ParameterNotFoundException extends Exception {
	      public ParameterNotFoundException(String message) {
	         super(message);
	      }
	 }
	
	class ParameterWrongType extends Exception {
	      public ParameterWrongType(String message) {
	         super(message);
	      }
	 }
}
