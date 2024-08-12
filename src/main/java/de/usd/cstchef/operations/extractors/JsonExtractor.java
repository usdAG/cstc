package de.usd.cstchef.operations.extractors;

import java.util.LinkedHashMap;

import javax.swing.JTextField;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.spi.json.JsonProvider;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Get JSON", category = OperationCategory.EXTRACTORS, description = "Extracts values of JSON objects.")
public class JsonExtractor extends Operation {

    private static JsonProvider provider;

    //TODO should this be a VariableTextField?
    protected JTextField fieldTxt;

    public JsonExtractor(){
        this(new String());
    }

    public JsonExtractor(String key) {
        super();
        if (JsonExtractor.provider == null) {
            JsonExtractor.provider = Configuration.defaultConfiguration().jsonProvider();
        }
        this.setKey(key);
    }

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        if( fieldTxt.getText().equals("") )
            return factory.createByteArray(0);

        Object document = provider.parse(input.toString());
        Object result = JsonPath.read(document, fieldTxt.getText());

        return factory.createByteArray(result.toString());
    }

    @Override
    public void createUI() {
        this.fieldTxt = new JTextField();
        this.addUIElement("Field", this.fieldTxt);
    }
    
    public void setKey(String key){
        this.fieldTxt.setText(key);
    }

}
