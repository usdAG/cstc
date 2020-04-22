package de.usd.cstchef.operations.extractors;

import javax.swing.JTextField;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.spi.json.JsonProvider;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

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

        if( fieldTxt.getText().equals("") )
            return input;

		Object document = provider.parse(new String(input));
		Object result = JsonPath.read(document, fieldTxt.getText());

		if( result == null )
			result = "null";
		
		Class<? extends Object> resultClass = result.getClass();
		
		if( resultClass == String.class ) {
			return ((String)result).getBytes();
		} else if( resultClass == Integer.class || resultClass == Float.class || resultClass == Double.class ) {
			return String.valueOf(result).getBytes();
		} else if( resultClass == Boolean.class ) {
			return String.valueOf(result).getBytes();
		}
		
		throw new IllegalArgumentException("JSON data of unknown type.");
	}

	@Override
	public void createUI() {
		this.fieldTxt = new JTextField();
		this.addUIElement("Field", this.fieldTxt);
	}

}
