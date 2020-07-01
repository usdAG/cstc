package de.usd.cstchef.operations.signature;

import java.awt.event.ActionEvent;
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
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import de.usd.cstchef.view.ui.FormatTextField;

public abstract class XmlSignature extends KeystoreOperation {

    private boolean multiSignature = false;
    private XMLSignatureFactory signatureFac;
    private HashMap<String, String> digestMethods = new HashMap<String,String>();
    private HashMap<String, String> signatureMethods = new HashMap<String,String>();    
    //"rsa-sha256", SignatureMethod.RSA_SHA256,
    //"rsa-sha512", SignatureMethod.RSA_SHA512
    private String[] availDigestMethods = new String[] {"sha1", "sha256", "sha512"};
    private String[] availSignatureMethods = new String[] {"rsa-sha1"};//, "rsa-sha256", "rsa-sha512"};

	protected JComboBox<String> signatureMethod;
	protected JComboBox<String> digestMethod;

	protected JButton addReferenceButton;
	protected JButton removeReferenceButton;
	protected ArrayList<FormatTextField> referenceFields = new ArrayList<FormatTextField>();
    
	protected JComboBox<String> includeKeyInfo;
    protected JCheckBox certificate;
    protected JCheckBox subject;
    protected JCheckBox issuer;
    protected JCheckBox serialIssuer;

	protected FormatTextField idIdentifier;

	public XmlSignature() {
		super();
		this.digestMethods.put("sha1", DigestMethod.SHA1);
		this.digestMethods.put("sha256", DigestMethod.SHA256);
		this.digestMethods.put("sha512", DigestMethod.SHA512);
		this.signatureMethods.put("rsa-sha1", SignatureMethod.RSA_SHA1);
        this.signatureFac = XMLSignatureFactory.getInstance("DOM");
        this.createMyUI();
	}

    protected ArrayList<Reference> getReferences() throws Exception {
      String digMethod = (String) digestMethod.getSelectedItem();
      ArrayList<Reference> referenceList = new ArrayList<Reference>();
      if( referenceFields != null && referenceFields.size() > 0)  {
        for( FormatTextField field : referenceFields ) {
          String referenceString = new String(field.getText());
          Reference ref = signatureFac.newReference("#" + referenceString, signatureFac.newDigestMethod(digestMethods.get(digMethod), null), Collections.singletonList (signatureFac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null, null);
          referenceList.add(ref);
        }
      } else {
        Reference ref = signatureFac.newReference("", signatureFac.newDigestMethod(digestMethods.get(digMethod), null), Collections.singletonList (signatureFac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null, null);
        referenceList.add(ref);
      }
      return referenceList;
    }


    protected void validateIdAttributes(Document doc) throws Exception {
      String idAttribute = new String(idIdentifier.getText());
      if( idAttribute == null || idAttribute.isEmpty() ) {
        return;
      }
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


    protected KeyInfo getKeyInfo() throws Exception {
      PrivateKeyEntry keyEntry = this.selectedEntry;
      String keyInfoChoice = (String) includeKeyInfo.getSelectedItem();
      if( Boolean.parseBoolean(keyInfoChoice) ) {
        X509Certificate cert = (X509Certificate)keyEntry.getCertificate();
        KeyInfoFactory keyInfoFac = signatureFac.getKeyInfoFactory();
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
        return keyInfoFac.newKeyInfo(Collections.singletonList(xd));
      }
      return (KeyInfo)null;
    }
    

    protected void createSignature(Document document) throws Exception {
      String signMethod = (String)signatureMethod.getSelectedItem();
      PrivateKeyEntry keyEntry = this.selectedEntry;

      if( this.multiSignature )
        this.validateIdAttributes(document);
      ArrayList<Reference> references = this.getReferences();
      SignedInfo signatureInfo = signatureFac.newSignedInfo(signatureFac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec)null), signatureFac.newSignatureMethod(signatureMethods.get(signMethod), null), references);
      KeyInfo keyInfo = this.getKeyInfo();
      XMLSignature signature = signatureFac.newXMLSignature(signatureInfo, keyInfo);

      DOMSignContext dsc = new DOMSignContext (keyEntry.getPrivateKey(), document.getDocumentElement()); 
      signature.sign(dsc);
    }


    protected void addIdSelectors() {
        this.multiSignature = true;

		this.idIdentifier = new FormatTextField();
		this.addUIElement("Identifier", this.idIdentifier);

		addReferenceButton = new JButton("Add Reference");
		addReferenceButton.addActionListener(this);
		this.addUIElement(null, addReferenceButton, "button1");
    }


	public void createMyUI() {
        super.createMyUI();

		this.includeKeyInfo = new JComboBox<>(new String[]{ "true", "false" });
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
