package de.usd.cstchef.operations.signature;

import java.security.Signature;

import javax.swing.JComboBox;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "RSA Signature", category = OperationCategory.SIGNATURE, description = "Create an RSA signature")
public class RsaSignature extends KeystoreOperation {

	private static String[] inOutModes = new String[] { "Raw", "Hex", "Base64" };
	
	protected JComboBox<String> algos;
	protected JComboBox<String> inputMode;
	protected JComboBox<String> outputMode;
	
	public RsaSignature() {
		super();
		this.createMyUI();
	}

	protected byte[] perform(byte[] input) throws Exception {
		
		if( !this.keyAvailable.isSelected() )
			throw new IllegalArgumentException("No private key available.");
		
		String algo = (String)algos.getSelectedItem();
		Signature signature = Signature.getInstance(algo);
		
		String selectedInputMode = (String)inputMode.getSelectedItem();
        String selectedOutputMode = (String)outputMode.getSelectedItem();
        
        if( selectedInputMode.equals("Hex") )
        	input = Hex.decode(input);
        if( selectedInputMode.equals("Base64") )
        	input = Base64.decode(input);
        
		signature.initSign(this.selectedEntry.getPrivateKey());
		signature.update(input);
		byte[] result = signature.sign();
		
		if( selectedOutputMode.equals("Hex") )
			result = Hex.encode(result);
		if( selectedOutputMode.equals("Base64") )
			result = Base64.encode(result);
		
		return result;
	}
	
	public void createMyUI() {

        super.createMyUI();
		SignatureUtils utils = SignatureUtils.getInstance();

		this.algos = new JComboBox<>(utils.getRsaAlgos());
		this.addUIElement("Padding", this.algos);

		this.inputMode = new JComboBox<>(inOutModes);
		this.addUIElement("Input", this.inputMode);

		this.outputMode = new JComboBox<>(inOutModes);
		this.addUIElement("Output", this.outputMode);
	}
}
