package de.usd.cstchef.operations.misc;

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
    protected byte[] perform(byte[] input) throws Exception {
        return String.format("GET %s HTTP/1.1\n" + //
                "Host: %s\n" + //
                "Accept: %s", document.getText(), host.getText(), accept.getText()).getBytes();
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
