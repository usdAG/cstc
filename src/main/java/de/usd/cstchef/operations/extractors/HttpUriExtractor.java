package de.usd.cstchef.operations.extractors;

import java.util.Arrays;
import java.util.List;

import javax.swing.JCheckBox;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Get HTTP URI", category = OperationCategory.EXTRACTORS, description = "Extracts the URI of a HTTP request.")
public class HttpUriExtractor extends Operation {

    protected JCheckBox checkbox;

    @Override
    public void createUI() {
        this.checkbox = new JCheckBox("With parameters");
        this.checkbox.setSelected(true);
        this.addUIElement(null, this.checkbox, "checkbox1");
    }

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        if (messageType == MessageType.REQUEST) {
            try {
                String url = factory.createHttpRequest(input).url();
                if (!checkbox.isSelected()) {
                    return factory.createByteArray(url.split("\\?")[0]);
                } else {
                    return factory.createByteArray(url);
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
}
