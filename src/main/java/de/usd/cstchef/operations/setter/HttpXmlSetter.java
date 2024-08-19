package de.usd.cstchef.operations.setter;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;

import javax.swing.JCheckBox;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "Set HTTP XML", category = OperationCategory.SETTER, description = "Set a XML parameter to the specified value.")
public class HttpXmlSetter extends SetterOperation {

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String parameterName = getWhere();
        if (parameterName.equals(""))
            return input;

        if (messageType == MessageType.REQUEST) {
            try {
                HttpRequest request = HttpRequest.httpRequest(input);
                if (request.hasParameter(parameterName, HttpParameterType.XML)) {
                    return request
                            .withParameter(HttpParameter.parameter(parameterName, getWhat(), HttpParameterType.XML))
                            .toByteArray();
                } else {
                    return input;
                }
            } catch (Exception e) {
                throw new IllegalArgumentException("Input is not a valid request");
            }
        } else if (messageType == MessageType.RESPONSE) {
            HttpResponse response = HttpResponse.httpResponse(input);
            DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(response.bodyToString().getBytes()));
            doc.getDocumentElement().normalize();
            NodeList nodeList = doc.getElementsByTagName(parameterName);
            Element first = (Element) nodeList.item(0);
            if (first != null) {
                first.setTextContent(getWhat());
            }
            else{
                throw new IllegalArgumentException("Parameter could not be found");
            }
            DOMSource domSource = new DOMSource(doc);
            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.transform(domSource, result);
            return response.withBody(writer.toString()).toByteArray();
        } else {
            return parseRawMessage(input);
        }

    }

}
