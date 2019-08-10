package de.usd.cstchef.operations.setter;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.Reader;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "HTTP SET Uri", category = OperationCategory.SETTER, description = "Sets the given variable as the uri.")
public class HttpSetUri extends Operation {

	private VariableTextField uriTxt;

	@Override
	public void createUI() {
		this.uriTxt = new VariableTextField();
		this.addUIElement("Uri", this.uriTxt);
	}

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		try {
			// Request-Line = Method SP Request-URI SP HTTP-Version CRLF
			String newUri = this.uriTxt.getText();
			Reader in = new InputStreamReader(new ByteArrayInputStream(input));
			BufferedReader reader = new BufferedReader(in);
			String requestLine = reader.readLine();
			String[] parts = requestLine.split(" ", 3);
			StringBuffer buf = new StringBuffer();
			String newRequestLine = String.format("%s %s %s", parts[0], newUri, parts[2]);
			// TODO is there a better way to do this?
			buf.append(newRequestLine).append("\n");
			String line;
			while ((line = reader.readLine()) != null) {
				buf.append(line).append("\n");
			}
			
			return buf.toString().getBytes();
		} catch (Exception e) {
			throw new IllegalArgumentException("Provided input is not a valid http request.");
		}
	}

}
