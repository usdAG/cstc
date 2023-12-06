package de.usd.cstchef.operations.setter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;


import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.view.ui.VariableTextField;

public abstract class SetterOperation extends Operation {

    private VariableTextField whereToSet;
    private VariableTextField whatToSet;

    @Override
    public void createUI() {
        this.whereToSet = new VariableTextField();
        this.whatToSet = new VariableTextField();
        this.addUIElement("Key", this.whereToSet);
        this.addUIElement("Value", this.whatToSet);
    }

    protected String getWhere() {
        return whereToSet.getText();
    }

    protected ByteArray getWhereBytes() {
        return whereToSet.getBytes();
    }

    protected String getWhat() {
        return whatToSet.getText();
    }

    protected ByteArray getWhatBytes() {
        return whatToSet.getBytes();
    }

    // This is required because Burps getRequestParameter returns always the first occurrence of the parameter name.
    // If you have e.g. a cookie with the same name as the POST parameter, you have no chance of getting the POST
    // parameter using getRequestParameter (at least I do not know how).
    protected ParsedHttpParameter getParameter(ByteArray request, String paramName, HttpParameterType type, MontoyaApi api) {

        List<ParsedHttpParameter> parameters = HttpRequest.httpRequest(request).parameters();
        ParsedHttpParameter param = null;

        for(ParsedHttpParameter p:parameters) {
            if( p.name().equals(paramName) )
                if( p.type().equals(type) ) {
                    param = p;
                    break;
                }
        }
        return param;
    }

    protected ByteArray urlEncode(ByteArray input, boolean all, MontoyaApi api) throws IOException {

        ByteArray newValue = input;

        if( all ) {
            byte[] delimiter = "%".getBytes();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(delimiter);

            for (int i = 0; i < newValue.length() - 1; i++) {
                out.write(Hex.encode(new byte[] { newValue.getByte(i) }));
                out.write(delimiter);
            }

            out.write(Hex.encode(new byte[] { newValue.getByte(newValue.length() - 1) }));
            newValue = factory.createByteArray(out.toByteArray());

        } else {
            newValue = api.utilities().urlUtils().encode(input);
        }

        return newValue;
    }

    protected ByteArray replaceParam(ByteArray request, ParsedHttpParameter param, ByteArray newValue) {

        int length = request.length();
        int start = param.valueOffsets().startIndexInclusive();
        int end = param.valueOffsets().endIndexExclusive();

        ByteArray prefix = request.subArray(0, start);
        ByteArray rest = request.subArray(end, length);        
        
        ByteArray newRequest = prefix.withAppended(newValue).withAppended(rest);

        return newRequest;
    }
}
