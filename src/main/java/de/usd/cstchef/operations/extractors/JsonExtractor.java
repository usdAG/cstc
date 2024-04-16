package de.usd.cstchef.operations.extractors;

import javax.swing.JTextField;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.spi.json.JsonProvider;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "JSON", category = OperationCategory.EXTRACTORS, description = "Extracts values of JSON objects.")
public class JsonExtractor extends Operation {

    private static JsonProvider provider;

    //TODO should this be a VariableTextField?
    private JTextField fieldTxt;

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
            return ByteArray.byteArray(0);

        Object document = provider.parse(input.toString());
        Object result = JsonPath.read(document, fieldTxt.getText());

        if( result == null )
            result = "null";

        Class<? extends Object> resultClass = result.getClass();

        if( resultClass == String.class ) {
            return factory.createByteArray((String)result);
        } else if( resultClass == Integer.class || resultClass == Float.class || resultClass == Double.class ) {
            return  factory.createByteArray((String)result);
        } else if( resultClass == Boolean.class ) {
            return  factory.createByteArray(checkNull((String)result));
        }

        throw new IllegalArgumentException("JSON data of unknown type.");
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
