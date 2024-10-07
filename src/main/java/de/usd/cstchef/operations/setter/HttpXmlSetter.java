package de.usd.cstchef.operations.setter;

import javax.swing.JCheckBox;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextField;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Set HTTP XML", category = OperationCategory.SETTER, description = "Set a XML parameter to the specified value.\nUse XPath Syntax.")
public class HttpXmlSetter extends Operation {

    private VariableTextField path;
    private VariableTextField value;
    private JCheckBox addIfNotPresent;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String p = this.path.getText();
        String v = this.value.getText();

        if(p.trim().isEmpty()) {
            return input;
        }

        if(messageType == MessageType.REQUEST || messageType == MessageType.RESPONSE) {
            return HttpRequest.httpRequest(input).withBody(Utils.xmlSetter(HttpRequest.httpRequest(input).body(), p, v, addIfNotPresent.isSelected())).toByteArray();
        }
        else if(messageType == MessageType.RESPONSE) {
            return HttpResponse.httpResponse(input).withBody(Utils.xmlSetter(HttpResponse.httpResponse(input).body(), p, v, addIfNotPresent.isSelected())).toByteArray();
        }
        else {
            return parseRawMessage(input);
        }
    }

    @Override
    public void createUI() {
        this.path = new VariableTextField();
        this.value = new VariableTextField();
        this.addIfNotPresent = new JCheckBox("Add if not present");

        this.addUIElement("Path", this.path);
        this.addUIElement("Value", this.value);
        this.addUIElement(null, this.addIfNotPresent, "checkbox1");
    }

}
