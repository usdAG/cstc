package de.usd.cstchef.operations.extractors;

import javax.swing.JTextField;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.spi.json.JsonProvider;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "JSON", category = OperationCategory.EXTRACTORS, description = "Extracts values of json objects.")
public class JsonExtractor extends Operation {

	private static JsonProvider provider;

	//TODO should this be a VariableTextField?
	private JTextField fieldTxt;

	public JsonExtractor() {
		super();
		if (JsonExtractor.provider == null) {
			JsonExtractor.provider = Configuration.defaultConfiguration().jsonProvider();
		}
	}

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		Object document = provider.parse(new String(input));
		String result = JsonPath.read(document, fieldTxt.getText());

		return result.getBytes();
	}

	@Override
	public void createUI() {
		this.fieldTxt = new JTextField();
		this.addUIElement("Field", this.fieldTxt);
	}

}
