package de.usd.cstchef.operations.setter;

import javax.swing.JCheckBox;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IParameter;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP POST Param", category = OperationCategory.SETTER, description = "Set a POST parameter to the specified value.")
public class HttpPostSetter extends SetterOperation {

	private JCheckBox addIfNotPresent;
	private JCheckBox urlEncode;
	private JCheckBox urlEncodeAll;
	
	@Override
	protected byte[] perform(byte[] input) throws Exception {
		
		String parameterName = getWhere();
		if( parameterName.equals("") )
			return input;
			
		IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
		IExtensionHelpers helpers = callbacks.getHelpers();
		
		byte[] newValue = getWhatBytes();
	
		if( urlEncodeAll.isSelected() || urlEncode.isSelected() )
			newValue = urlEncode(newValue, urlEncodeAll.isSelected(), helpers);
		
		IParameter param = getParameter(input, parameterName, IParameter.PARAM_BODY, helpers);
		
		if( param == null ) {
			
			if( !addIfNotPresent.isSelected() )
				return input; 
			
			param = helpers.buildParameter(parameterName, "dummy", IParameter.PARAM_BODY);
			input = helpers.addParameter(input, param);
			param = getParameter(input, parameterName, IParameter.PARAM_BODY, helpers);
			if( param == null )
				// This case occurs when the HTTP request is a JSON or XML request. Burp does not
				// support adding parameters to these and therefore the request should stay unmodified.
				throw new IllegalArgumentException("Failure while adding the parameter. Operation cannot be used on XML or JSON.");
		}

		byte[] newRequest = replaceParam(input, param, newValue);
		return newRequest;
	}

	@Override
	public void createUI() {
		super.createUI();

		this.urlEncode = new JCheckBox("URL encode");
	    this.urlEncode.setSelected(false);
		this.addUIElement(null, this.urlEncode);
		
		this.urlEncodeAll = new JCheckBox("URL encode all");
	    this.urlEncodeAll.setSelected(false);
		this.addUIElement(null, this.urlEncodeAll);
		
		this.addIfNotPresent = new JCheckBox("Add if not present");
	    this.addIfNotPresent.setSelected(true);
		this.addUIElement(null, this.addIfNotPresent);
	}
	
}
