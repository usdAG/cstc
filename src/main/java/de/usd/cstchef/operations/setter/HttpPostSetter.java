package de.usd.cstchef.operations.setter;

import javax.swing.JCheckBox;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP POST Param", category = OperationCategory.SETTER, description = "Set a POST parameter to the specified value.")
public class HttpPostSetter extends SetterOperation {

    private JCheckBox addIfNotPresent;
    private JCheckBox urlEncode;
    private JCheckBox urlEncodeAll;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String parameterName = getWhere();
        if( parameterName.equals("") )
            return input;

        MontoyaApi api = BurpUtils.getInstance().getApi();

        ByteArray newValue = getWhatBytes();

        if( urlEncodeAll.isSelected() || urlEncode.isSelected() )
            newValue = urlEncode(newValue, urlEncodeAll.isSelected(), api);

        ParsedHttpParameter param = getParameter(input, parameterName, HttpParameterType.BODY, api);

        if( param == null ) {

            if( !addIfNotPresent.isSelected() )
                return input;

            HttpRequest.httpRequest(input).withAddedParameters(HttpParameter.bodyParameter(parameterName, "dummy"));
            param = getParameter(input, parameterName, HttpParameterType.BODY, api);
            if( param == null )
                // This case occurs when the HTTP request is a JSON or XML request. Burp does not
                // support adding parameters to these and therefore the request should stay unmodified.
                throw new IllegalArgumentException("Failure while adding the parameter. Operation cannot be used on XML or JSON.");
        }

        ByteArray newRequest = replaceParam(input, param, newValue);
        return newRequest;
    }

    @Override
    public void createUI() {
        super.createUI();

        this.urlEncode = new JCheckBox("URL encode");
        this.urlEncode.setSelected(false);
        this.addUIElement(null, this.urlEncode, "checkbox1");

        this.urlEncodeAll = new JCheckBox("URL encode all");
        this.urlEncodeAll.setSelected(false);
        this.addUIElement(null, this.urlEncodeAll, "checkbox2");

        this.addIfNotPresent = new JCheckBox("Add if not present");
        this.addIfNotPresent.setSelected(true);
        this.addUIElement(null, this.addIfNotPresent, "checkbox3");
    }

}
