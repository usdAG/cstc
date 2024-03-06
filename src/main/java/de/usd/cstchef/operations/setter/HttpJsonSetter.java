package de.usd.cstchef.operations.setter;

import java.awt.Color;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;

import javax.swing.JCheckBox;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.extractors.JsonExtractor;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "HTTP JSON", category = OperationCategory.SETTER, description = "Set a JSON parameter to the specified value.")
public class HttpJsonSetter extends SetterOperation {

    private JCheckBox addIfNotPresent;
    private VariableTextField path;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String parameterName = getWhere();
        if (parameterName.equals(""))
            return input;

        if (messageType == MessageType.REQUEST) {
            return HttpRequest.httpRequest(input)
                    .withParameter(HttpParameter.parameter(parameterName, getWhat(), HttpParameterType.JSON))
                    .toByteArray();
        } else if (messageType == MessageType.RESPONSE) {
            HttpResponse response = HttpResponse.httpResponse(input);
            return response.withBody(Utils.jsonSetter(response.body(), parameterName, getWhat(),
                    addIfNotPresent.isSelected(), path.getText())).toByteArray();

        } else {
            return parseRawMessage(input);
        }
    }

    @Override
    public void createUI() {
        super.createUI();

        this.addIfNotPresent = new JCheckBox("Add if not present");
        this.addIfNotPresent.setSelected(true);
        this.addUIElement(null, this.addIfNotPresent, "checkbox1");

        this.path = new VariableTextField();
        this.path.setText("Insert-Path");
        this.path.setForeground(Color.GRAY);
        this.path.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {
                if (path.getText().equals("Insertion Path")) {
                    path.setText("");
                    path.setForeground(null);
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (path.getText().isEmpty()) {
                    path.setForeground(Color.GRAY);
                    path.setText("Insertion Path");
                }
            }
        });
        this.addUIElement(null, this.path, "textbox1");
    }
}
