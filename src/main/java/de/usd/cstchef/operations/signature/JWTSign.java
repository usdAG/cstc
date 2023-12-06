package de.usd.cstchef.operations.signature;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextField;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.swing.JComboBox;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.apache.commons.lang3.NotImplementedException;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import burp.Logger;
import burp.api.montoya.core.ByteArray;

@OperationInfos(name = "JWT Sign", category = OperationCategory.SIGNATURE, description = "Sign a given JWT payload")
public class JWTSign extends Operation implements ActionListener, DocumentListener {

	private VariableTextField secretValue;
	private JComboBox<AlgorithmItem> algorithms; 
	private Algorithm currentAlgorithm;	
	private boolean hasError= false;
	
	@Override
	protected ByteArray perform(ByteArray input) throws Exception {
		if(this.hasError) {			
			throw new IllegalArgumentException("Key not valid");
		}
		String token = JWT.create().withPayload(input.toString()).sign(this.currentAlgorithm);
		return factory.createByteArray(token);
	}

    public void createUI() {
    	this.secretValue = new VariableTextField();
    	this.secretValue.getDocument().addDocumentListener(this);
    	this.secretValue.setText("");
    
        this.addUIElement("Secret or Key", this.secretValue);
        
        this.algorithms = new JComboBox();        
        this.algorithms.addItem(AlgorithmItem.HS256);
        this.algorithms.addItem(AlgorithmItem.HS384);
        this.algorithms.addItem(AlgorithmItem.HS512);
        this.algorithms.addItem(AlgorithmItem.RSA256);
        this.algorithms.addItem(AlgorithmItem.RSA384);
        this.algorithms.addItem(AlgorithmItem.RSA512);
        this.algorithms.addActionListener(this);
        this.algorithms.setSelectedIndex(0);
        this.addUIElement("Algorithm to sign the JWT with", algorithms);
    }
    
    private void reconfigureAlgorithmAndKey() {
    	try {
    		AlgorithmItem item = (AlgorithmItem)this.algorithms.getSelectedItem();
    		String secret = this.secretValue.getText();
    		switch(item){		
    			case HS256:
    				this.currentAlgorithm = Algorithm.HMAC256(secret);    				
    				break;
    			case HS384:
    				this.currentAlgorithm = Algorithm.HMAC384(secret);    				
    				break;
    			case HS512:
    				this.currentAlgorithm = Algorithm.HMAC512(secret);    				
    				break;
    			case RSA256:				
    				this.currentAlgorithm = Algorithm.RSA256(this.createKeyFromString(secret));
    				break;
    			case RSA384:				
    				this.currentAlgorithm = Algorithm.RSA384(this.createKeyFromString(secret));
    				break;
    			case RSA512:				
    				this.currentAlgorithm = Algorithm.RSA512(this.createKeyFromString(secret));
    				break;
    			default:
    				throw new NotImplementedException("Chosen algorithm unknown");
    		}
    		this.hasError=false;
    	}
    	catch(Exception ex) {    		
    		this.hasError=true;
    	}
    	
    	
    }
    
	@Override
	public void actionPerformed(ActionEvent e) {
		this.reconfigureAlgorithmAndKey();
	}
	
	private RSAKey createKeyFromString(String input) throws Exception {
		StringBuilder pkcs8Lines = new StringBuilder();
		BufferedReader rdr = new BufferedReader(new StringReader(input));
		String line;
		while ((line = rdr.readLine()) != null) {
		    pkcs8Lines.append(line);
		}
		
		String pkcs8Pem = pkcs8Lines.toString();
		pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "");
		pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "");
		pkcs8Pem = pkcs8Pem.replaceAll("\\s+","");
		
		byte [] pkcs8EncodedBytes = Base64.getDecoder().decode(pkcs8Pem);

		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		RSAPrivateKey privKey = (RSAPrivateKey)kf.generatePrivate(keySpec);
		return privKey;
	}
	
	private enum AlgorithmItem{	
		 HS256("HS256"), HS384("HS384"), HS512("HS512"), RSA256("RSA256"), RSA384("RSA384"), RSA512("RSA512");
	        private String name;
	        private AlgorithmItem(String name) {
	            this.name = name;
	        }
	       
	        @Override
	        public String toString(){
	            return name;
	        }
	}

	@Override
	public void insertUpdate(DocumentEvent e) {
		this.reconfigureAlgorithmAndKey();		
	}

	@Override
	public void removeUpdate(DocumentEvent e) {
		this.reconfigureAlgorithmAndKey();		
	}

	@Override
	public void changedUpdate(DocumentEvent e) {
		this.reconfigureAlgorithmAndKey();
	}
}
