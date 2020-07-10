package de.usd.cstchef.operations.signature;

import java.awt.event.ActionEvent;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.FormatTextField;

@OperationInfos(name = "Soap Multi Signature", category = OperationCategory.SIGNATURE, description = "Create a Soap signature.")
public class SoapMultiSignature extends KeystoreOperation {

    public SoapMultiSignature() {
      super();
      this.digestMethods.put("sha1", DigestMethod.SHA1);
	  this.digestMethods.put("sha256", DigestMethod.SHA256);
	  this.digestMethods.put("sha512", DigestMethod.SHA512);
	  this.signatureMethods.put("rsa-sha1", SignatureMethod.RSA_SHA1);
      this.createMyUI();
    }

    protected HashMap<String, String> digestMethods = new HashMap<String,String>();
    protected HashMap<String, String> signatureMethods = new HashMap<String,String>();    
    //"rsa-sha256", SignatureMethod.RSA_SHA256,
    //"rsa-sha512", SignatureMethod.RSA_SHA512

    protected String[] availDigestMethods = new String[] {"sha1", "sha256", "sha512"};
    protected String[] availSignatureMethods = new String[] {"rsa-sha1"};//, "rsa-sha256", "rsa-sha512"};
	protected String[] includeKeyInfos = new String[] { "true", "false" };
	protected JComboBox<String> includeKeyInfo;
	protected JComboBox<String> signatureMethod;
	protected JComboBox<String> digestMethod;
	protected JButton addReferenceButton;
	protected FormatTextField idIdentifier;
	protected ArrayList<FormatTextField> referenceFields = new ArrayList<FormatTextField>();
    protected JCheckBox certificate;
    protected JCheckBox subject;
    protected JCheckBox issuer;
    protected JCheckBox serialIssuer;


    private ArrayList<Reference> getReferences(XMLSignatureFactory fac) throws Exception {
      String digMethod = (String) digestMethod.getSelectedItem();
      ArrayList<Reference> referenceList = new ArrayList<Reference>();
      if( referenceFields != null && referenceFields.size() > 0)  {
        PrintWriter writer = new PrintWriter("/tmp/test", "UTF-8");
        writer.println("test");
        writer.close();
        for( FormatTextField field : referenceFields ) {
          String referenceString = new String(field.getText());
          Reference ref = fac.newReference("#" + referenceString, fac.newDigestMethod(digestMethods.get(digMethod), null), Collections.singletonList (fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null, null);
          referenceList.add(ref);
        }
      } else {
        Reference ref = fac.newReference("", fac.newDigestMethod(digestMethods.get(digMethod), null), Collections.singletonList (fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null, null);
        referenceList.add(ref);
      }
      return referenceList;
    }

    private void validateIdAttributes(Document doc) throws Exception {
      String idAttribute = new String(idIdentifier.getText());
      XPathFactory xPathfactory = XPathFactory.newInstance();
      XPath xpath = xPathfactory.newXPath();
      XPathExpression expr = xpath.compile("descendant-or-self::*/@" + idAttribute);
      NodeList nodeList = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
      if(nodeList != null && nodeList.getLength() > 0) {
        for(int j = 0; j < nodeList.getLength(); j++) {
            Attr attr = (Attr)nodeList.item(j);
            ((Element)attr.getOwnerElement()).setIdAttributeNode(attr,true);
        }
      }
    }

    private KeyInfo getKeyInfo(XMLSignatureFactory fac, PrivateKeyEntry keyEntry) throws Exception {
      String keyInfoChoice = (String) includeKeyInfo.getSelectedItem();
      if( Boolean.parseBoolean(keyInfoChoice) ) {
        KeyInfo keyInfo;
        X509Certificate cert = (X509Certificate)keyEntry.getCertificate();
        KeyInfoFactory keyInfoFac = fac.getKeyInfoFactory();
        List<Object> x509Content = new ArrayList<Object>();
        if( this.subject.isSelected() ) {
          x509Content.add(cert.getSubjectX500Principal().getName());
        } 
        if( this.serialIssuer.isSelected() ) {
          x509Content.add(keyInfoFac.newX509IssuerSerial(cert.getIssuerX500Principal().getName(),cert.getSerialNumber()));
        }
        if( this.issuer.isSelected() ) {
          x509Content.add(cert.getIssuerX500Principal().getName());
        }
        if( this.certificate.isSelected() ) {
          x509Content.add(cert);
        }
        X509Data xd = keyInfoFac.newX509Data(x509Content);
        keyInfo = keyInfoFac.newKeyInfo(Collections.singletonList(xd));
        return keyInfo;
      }
      return (KeyInfo)null;
    }


	protected byte[] perform(byte[] input) throws Exception {

      String signMethod = (String)signatureMethod.getSelectedItem();
      PrivateKeyEntry keyEntry = this.selectedEntry;

      XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
      ArrayList<Reference> references = getReferences(fac);
      SignedInfo signatureInfo = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec)null), fac.newSignatureMethod(signatureMethods.get(signMethod), null), references);
      KeyInfo keyInfo = this.getKeyInfo(fac, keyEntry);
      XMLSignature signature = fac.newXMLSignature(signatureInfo, keyInfo);

      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
      dbf.setNamespaceAware(true);
      Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(input));
      try {
        validateIdAttributes(doc);
      } catch( Exception e ) {
        throw new IllegalArgumentException("Provided Id identifier seems to be invalid.");
      }
      DOMSignContext dsc = new DOMSignContext (keyEntry.getPrivateKey(), doc.getDocumentElement()); 
      signature.sign(dsc);

      DOMSource source = new DOMSource(doc);
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      StreamResult result = new StreamResult(bos);
      TransformerFactory transformerFactory = TransformerFactory.newInstance();
      Transformer transformer = transformerFactory.newTransformer();
      transformer.transform(source, result);
      return bos.toByteArray();
	}

	public void createMyUI() {
        super.createMyUI();

		this.includeKeyInfo = new JComboBox<>(this.includeKeyInfos);
		this.includeKeyInfo.addActionListener(this);
		this.addUIElement("IncludeKeyInfo", this.includeKeyInfo);
        
        this.certificate = new JCheckBox("Include Certificate");
        this.certificate.setSelected(false);
		this.certificate.addActionListener(this);
		this.addUIElement(null, this.certificate, "checkbox1");

        this.subject = new JCheckBox("Include Subject");
        this.subject.setSelected(false);
		this.subject.addActionListener(this);
		this.addUIElement(null, this.subject, "checkbox2");

        this.issuer = new JCheckBox("Include Issuer");
        this.issuer.setSelected(false);
		this.issuer.addActionListener(this);
		this.addUIElement(null, this.issuer, "checkbox3");

        this.serialIssuer = new JCheckBox("Include Issuer");
        this.serialIssuer.setSelected(false);
		this.serialIssuer.addActionListener(this);
		this.addUIElement(null, this.serialIssuer, "checkbox4");
    
		this.digestMethod = new JComboBox<String>(this.availDigestMethods);
		this.digestMethod.addActionListener(this);
		this.addUIElement("DigestMethod", this.digestMethod);

		this.signatureMethod = new JComboBox<String>(this.availSignatureMethods);
		this.signatureMethod.addActionListener(this);
		this.addUIElement("SignatureMethod", this.signatureMethod);

		this.idIdentifier = new FormatTextField();
		this.addUIElement("Identifier", this.idIdentifier);

		addReferenceButton = new JButton("Add Reference");
		addReferenceButton.addActionListener(this);
		this.addUIElement(null, addReferenceButton, false, "button1");
	}

	public void actionPerformed(ActionEvent arg0) {
        if( arg0.getSource() == addReferenceButton ) {
          FormatTextField tmpRef = new FormatTextField();
          this.addUIElement("Reference", tmpRef);
          referenceFields.add(tmpRef);
        } else if( arg0.getSource() == this.includeKeyInfo) {
          String keyInfoChoice = (String) includeKeyInfo.getSelectedItem();
          if(!Boolean.parseBoolean(keyInfoChoice) ) {
            this.certificate.setVisible(false);
            this.subject.setVisible(false);
            this.issuer.setVisible(false);
            this.serialIssuer.setVisible(false);
          } else {
            this.certificate.setVisible(true);
            this.subject.setVisible(true);
            this.issuer.setVisible(true);
            this.serialIssuer.setVisible(true);
          }
        }
        super.actionPerformed(arg0);
	}
}
