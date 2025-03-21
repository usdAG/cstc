package de.usd.cstchef.operations.extractors;

import javax.swing.JCheckBox;

import burp.api.montoya.core.ByteArray;
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
    protected ByteArray perform(ByteArray input) throws Exception {

        MessageType messageType = parseMessageType(input);

        if (messageType == MessageType.REQUEST) {
            try {
                String url = factory.createHttpRequest(input).url();
                if (!checkbox.isSelected()) {
                    return factory.createByteArray(url.split("\\?")[0]);
                } else {
                    return factory.createByteArray(url);
                }
            } catch (Exception e) {
                throw new IllegalArgumentException("Input is not a valid request.");
            }
        } else if (messageType == MessageType.RESPONSE) {
            throw new IllegalArgumentException("Input is not a valid HTTP request.");
        } else {
            return parseRawMessage(input);
        }
    }
}
