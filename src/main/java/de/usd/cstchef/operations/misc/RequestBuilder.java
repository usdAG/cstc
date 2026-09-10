package de.usd.cstchef.operations.misc;

import javax.swing.JComboBox;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "Request Builder", category = OperationCategory.MISC, description = "Build a basic request to use in Send Plain Request.")
public class RequestBuilder extends Operation {

    private VariableTextField host;
    private VariableTextField document;
    private VariableTextField accept;
    private JComboBox<String> requestMethodBox;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        return factory.createByteArray(String.format("%s %s HTTP/1.1\r\n" + //
                "Host: %s\r\n" + //
                "Accept: %s\r\n\r\n", requestMethodBox.getSelectedItem(), document.getText(), host.getText(), accept.getText()));
    }

    @Override
    public void createUI() {
        this.requestMethodBox = new JComboBox<>(new String[] {"GET", "POST", "HEAD", "CONNECT", "PUT", "TRACE", "OPTIONS", "DELETE", "ACL", "ARBITRARY", "BASELINE-CONTROL", "BCOPY", "BDELETE", "BIND", "BMOVE", "BPROPFIND", "BPROPPATCH", "CHECKIN", "CHECKOUT", "COPY", "DEBUG", "INDEX", "LABEL", "LINK", "LOCK", "MERGE", "MKACTIVITY", "MKCALENDAR", "MKCOL", "MKREDIRECTREF", "MKWORKSPACE", "MOVE", "NOTIFY", "ORDERPATCH", "PATCH", "POLL", "PROPFIND", "PROPPATCH", "REBIND", "REPORT", "RPC_IN_DATA", "RPC_OUT_DATA", "SEARCH", "SUBSCRIBE", "TRACK", "UNBIND", "UNCHECKOUT", "UNLINK", "UNLOCK", "UNSUBSCRIBE", "UPDATE", "UPDATEREDIRECTREF", "VERSION-CONTROL", "X-MS-ENUMATTS"});
        this.addUIElement("Method", this.requestMethodBox);

        this.document = new VariableTextField();
        this.addUIElement("Document", this.document);

        this.host = new VariableTextField();
        this.addUIElement("Host", this.host);    

        this.accept = new VariableTextField();
        this.accept.setText("*/*");
        this.addUIElement("Accept", this.accept);
    }

}
