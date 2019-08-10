package de.usd.cstchef.operations.extractors;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.HashMap;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "HTTP header", category = OperationCategory.EXTRACTORS, description = "Extracts a header of a HTTP request.")
public class HttpHeaderExtractor extends Operation {

	private VariableTextField headerTxt;

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		HashMap<String, String> headers = new HashMap<>();

		try {

			Reader in = new InputStreamReader(new ByteArrayInputStream(input));
			BufferedReader reader = new BufferedReader(in);
			reader.readLine(); // skip first line

			String header = reader.readLine();
			while (header.length() > 0) {
				String[] values = header.split(":",2);
				headers.put(values[0].trim(), values[1].trim());
				header = reader.readLine();
			}
			String headerKey = headerTxt.getText();
			String headerValue = headers.getOrDefault(headerKey, "");
			
			return headerValue.getBytes();
			
		} catch (Exception e) {
			throw new IllegalArgumentException("Provided input is not a valid http request.");
		}
	}

	@Override
	public void createUI() {
		this.headerTxt = new VariableTextField();
		this.addUIElement("Name", this.headerTxt);
	}

}
