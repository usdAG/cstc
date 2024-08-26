package de.usd.cstchef.operations.setter;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;

import javax.swing.JCheckBox;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextField;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Set HTTP XML", category = OperationCategory.SETTER, description = "Set a XML parameter to the specified value.\nUse XPath Syntax.")
public class HttpXmlSetter extends SetterOperation {

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

        if (messageType == MessageType.REQUEST || messageType == MessageType.RESPONSE) {

            HttpMessage httpMessage;
            httpMessage = messageType == MessageType.REQUEST ? HttpRequest.httpRequest(input) : HttpResponse.httpResponse(input);

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            dbf.setXIncludeAware(false);
            // XXE
            dbf.setExpandEntityReferences(false);
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

            Document doc = messageType == MessageType.REQUEST ? dbf.newDocumentBuilder().parse(new ByteArrayInputStream(factory.createHttpRequest(input).bodyToString().getBytes())) : 
                dbf.newDocumentBuilder().parse(new ByteArrayInputStream(factory.createHttpResponse(input).bodyToString().getBytes()));
            doc.getDocumentElement().normalize();

            Element toAdd;

            XPath xPath = XPathFactory.newInstance().newXPath();
            NodeList nodeList;

            try {
                nodeList = (NodeList) xPath.compile(p).evaluate(doc, XPathConstants.NODESET);
            }
            catch(Exception e) {
                throw new IllegalArgumentException("Invalid XPath Syntax.");
            }

            for(int i = 0; i < nodeList.getLength(); i++) {
                nodeList.item(i).setTextContent(v);
            }

            if(nodeList.getLength() == 0 && addIfNotPresent.isSelected()) {
                if(p.matches(".*/@[a-zA-Z0-9-_.]*")) {
                    nodeList = (NodeList) xPath.compile(p.replaceAll("/@[a-zA-Z0-9-_.]*$", "")).evaluate(doc, XPathConstants.NODESET);
                    for(int i = 0; i < nodeList.getLength(); i++) {
                        ((Element) nodeList.item(i)).setAttribute(p.split("@")[p.split("@").length - 1], v);
                    }
                }
                else {
                    nodeList = (NodeList) xPath.compile(p.replaceAll("/[a-zA-Z0-9-_.]*$", "")).evaluate(doc, XPathConstants.NODESET);
                    for(int i = 0; i < nodeList.getLength(); i++) {
                        toAdd = doc.createElement(p.split("/")[p.split("/").length - 1]);
                        toAdd.setTextContent(v);
                        nodeList.item(i).appendChild(toAdd);
                    }
                }
            }

            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

            Transformer xformer = transformerFactory.newTransformer();
            xformer.setOutputProperty(OutputKeys.INDENT, "no");

            StringWriter output = new StringWriter();
            xformer.transform(new DOMSource(doc), new StreamResult(output));
            return messageType == MessageType.REQUEST ? ((HttpRequest)httpMessage).withBody(output.toString()).toByteArray() : ((HttpResponse)httpMessage).withBody(output.toString()).toByteArray();
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
        this.addUIElement(null, this.addIfNotPresent);
    }

}
