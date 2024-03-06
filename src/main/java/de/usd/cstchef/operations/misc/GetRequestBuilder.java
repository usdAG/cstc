package de.usd.cstchef.operations.misc;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "GET Request Builder", category = OperationCategory.MISC, description = "Build a basic GET request.")
public class GetRequestBuilder extends Operation {

    private VariableTextField host;
    private VariableTextField document;
    private VariableTextField accept;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {
        return factory.createByteArray(String.format("GET %s HTTP/1.1\n" + //
                "Host: %s\n" + //
                "Accept: %s", document.getText(), host.getText(), accept.getText()));
    }

    @Override
    public void createUI() {
        this.document = new VariableTextField();
        this.addUIElement("Document", this.document);

        this.host = new VariableTextField();
        this.addUIElement("Host", this.host);    

        this.accept = new VariableTextField();
        this.accept.setText("*/*");
        this.addUIElement("Accept", this.accept);
    }

}
