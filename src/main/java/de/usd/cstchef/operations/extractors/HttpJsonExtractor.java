package de.usd.cstchef.operations.extractors;

import java.util.Arrays;

import javax.swing.JTextField;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.spi.json.JsonProvider;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP JSON", category = OperationCategory.EXTRACTORS, description = "Get a JSON value from HTTP message.")
public class HttpJsonExtractor extends Operation {

    private JTextField fieldTxt;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String keyName = fieldTxt.getText();
        if( keyName.equals("") )
            return ByteArray.byteArray();

        

        if(messageType == MessageType.REQUEST){
            return ByteArray.byteArray(HttpRequest.httpRequest().parameter(keyName, HttpParameterType.JSON).value());
        }
        else if(messageType == MessageType.RESPONSE){
            JsonExtractor extractor = new JsonExtractor();
            return extractor.perform(HttpResponse.httpResponse(input).body(), messageType);
        }
        else{
            return parseRawMessage(input);
        }
    }

    @Override
    public void createUI() {
        this.fieldTxt = new JTextField();
        this.addUIElement("Field", this.fieldTxt);
    }
}
