package de.usd.cstchef.operations.setter;

import javax.swing.JCheckBox;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP GET Param", category = OperationCategory.SETTER, description = "Sets a GET parameter to the specified value.")
public class HttpGetSetter extends SetterOperation {

    private JCheckBox addIfNotPresent;
    private JCheckBox urlEncode;
    private JCheckBox urlEncodeAll;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String parameterName = getWhere();
        if (parameterName.equals(""))
            return input;

        if (messageType == MessageType.REQUEST) {
            try {
                HttpRequest request = HttpRequest.httpRequest(input);
                if (request.hasParameter(parameterName, HttpParameterType.URL) || addIfNotPresent.isSelected()) {
                    return request
                            .withParameter(HttpParameter.parameter(parameterName, getWhat(), HttpParameterType.URL))
                            .toByteArray();
                } else {
                    return input;
                }
            } catch (Exception e) {
                throw new IllegalArgumentException("Input is not a valid request");
            }
        } else if (messageType == MessageType.RESPONSE) {
            throw new IllegalArgumentException("Input is not a valid HTTP Request");
        } else {
            return parseRawMessage(input);
        }
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
