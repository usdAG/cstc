package de.usd.cstchef.operations.extractors;

import java.io.ByteArrayInputStream;

import javax.swing.JTextField;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameterType;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Get HTTP XML", category = OperationCategory.EXTRACTORS, description = "Extract the first occurrence of a XML value from HTTP message.")
public class HttpXmlExtractor extends Operation {

    protected JTextField fieldTxt;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        String keyName = fieldTxt.getText();
        if (keyName.equals(""))
            return factory.createByteArray(0);

        MessageType messageType = parseMessageType(input);

        if (messageType == MessageType.REQUEST) {
            try {
                return factory.createByteArray(checkNull(factory.createHttpRequest(input).parameterValue(keyName, HttpParameterType.XML)));
            } catch (Exception e) {
                throw new IllegalArgumentException("Input is not a valid request");
            }
        } else if (messageType == MessageType.RESPONSE) {
            DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(factory.createHttpResponse(input).bodyToString().getBytes()));
            doc.getDocumentElement().normalize();
            NodeList nodeList = doc.getElementsByTagName(keyName);
            try {
                return factory.createByteArray(checkNull(nodeList.item(0).getTextContent()));
            } catch (NullPointerException e) {
                throw new IllegalArgumentException("Input is not a valid request");
            }
        } else {
            return parseRawMessage(input);
        }
    }

    @Override
    public void createUI() {
        this.fieldTxt = new JTextField();
        this.addUIElement("Field", this.fieldTxt);
    }
}
