package de.usd.cstchef.operations.extractors;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.io.InputStream;

import javax.swing.JTextField;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP XML", category = OperationCategory.EXTRACTORS, description = "Extract the first occurrence of a XML value from HTTP message.")
public class HttpXmlExtractor extends Operation {

    private JTextField fieldTxt;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String keyName = fieldTxt.getText();
        if (keyName.equals(""))
            return ByteArray.byteArray(0);

        if (messageType == MessageType.REQUEST) {
            try {
                return checkNull(ByteArray
                        .byteArray(HttpRequest.httpRequest(input).parameterValue(keyName, HttpParameterType.XML)));
            } catch (Exception e) {
                throw new IllegalArgumentException("Input is not a valid request");
            }
        } else if (messageType == MessageType.RESPONSE) {
            DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(HttpResponse.httpResponse(input).bodyToString().getBytes()));
            doc.getDocumentElement().normalize();
            NodeList nodeList = doc.getElementsByTagName(keyName);
            return checkNull(ByteArray.byteArray(nodeList.item(0).getTextContent()));
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
