package de.usd.cstchef.operations.extractors;

import java.util.Arrays;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextArea;

@OperationInfos(name = "HTTP POST Parameter", category = OperationCategory.EXTRACTORS, description = "Extracts a POST parameter of a HTTP request.")
public class HttpPostExtractor extends Operation {

	protected VariableTextArea parameter;

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		try {
            String parameterString = parameter.getText() + "=";
			IBurpExtenderCallbacks cbs = BurpUtils.getInstance().getCallbacks();
			IRequestInfo requestInfo = cbs.getHelpers().analyzeRequest(input);
			int bodyOffset = requestInfo.getBodyOffset();

			String body = new String(Arrays.copyOfRange(input, bodyOffset, input.length));
            int start = body.indexOf(parameterString) + parameterString.length();
            int end = (body.indexOf('&', start) > 0) ? body.indexOf('&', start) : body.length();
			return body.substring(start, end).getBytes();
		} catch (Exception e) {
			throw new IllegalArgumentException("Provided input is not a valid http request.");
		}
	}

	@Override
	public void createUI() {
		this.parameter = new VariableTextArea();
		this.addUIElement("Parameter", this.parameter);
	}

}
