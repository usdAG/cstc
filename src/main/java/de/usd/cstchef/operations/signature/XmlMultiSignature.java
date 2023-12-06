package de.usd.cstchef.operations.signature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
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
      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
      dbf.setNamespaceAware(true);
      dbf.setXIncludeAware(false);
      dbf.setExpandEntityReferences(false);
      Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(input.getBytes()));

      this.createSignature(doc);

      DOMSource source = new DOMSource(doc);
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      StreamResult result = new StreamResult(bos);
      TransformerFactory transformerFactory = TransformerFactory.newInstance();
      Transformer transformer = transformerFactory.newTransformer();
      transformer.transform(source, result);
      return factory.createByteArray(bos.toByteArray());
    }

}
