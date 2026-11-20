package de.usd.cstchef.operations.signature;

import java.io.ByteArrayOutputStream;

import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Xml Multi Signature", category = OperationCategory.SIGNATURE, description = "Create a XML signature over specified fields.")
public class XmlMultiSignature extends XmlSignature {

    public XmlMultiSignature() {
      super();
      this.addIdSelectors();
    }

    protected ByteArray perform(ByteArray input) throws Exception {
      Document doc = this.parseXmlDocument(input);

      this.createSignature(doc);

      DOMSource source = new DOMSource(doc);
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      StreamResult result = new StreamResult(bos);
      javax.xml.transform.TransformerFactory transformerFactory = this.createSecureTransformerFactory();
      Transformer transformer = transformerFactory.newTransformer();
      transformer.transform(source, result);
      return factory.createByteArray(bos.toByteArray());
    }

}
