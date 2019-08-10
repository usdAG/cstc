package de.usd.cstchef.operations.extractors;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.Reader;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "HTTP GET Parameter", category = OperationCategory.EXTRACTORS, description = "Extracts a GET Parameter of a HTTP request.")
public class HttpGetExtractor extends Operation {

	protected VariableTextField parameter;

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		try {
			// Request-Line = Method SP Request-URI SP HTTP-Version CRLF
            String parameterString = parameter.getText() + '=';
			Reader in = new InputStreamReader(new ByteArrayInputStream(input));
			BufferedReader reader = new BufferedReader(in);
			String requestLine = reader.readLine();
			String[] parts = requestLine.split(" ");
            String params = (parts[1].split("\\?"))[1];
            int start = params.indexOf(parameterString) + parameterString.length();
            int end = (params.indexOf('&', start) > 0) ? params.indexOf('&', start) : params.length();
			return params.substring(start, end).getBytes();
		} catch (Exception e) {
			throw new IllegalArgumentException("Provided input seems not to contain GET parameters.");
		}
	}

	@Override
	public void createUI() {
		this.parameter = new VariableTextField();
		this.addUIElement("Parameter", this.parameter);
	}

}
