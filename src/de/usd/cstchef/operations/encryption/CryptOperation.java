package de.usd.cstchef.operations.encryption;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JComboBox;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.encryption.CipherUtils.CipherInfo;
import de.usd.cstchef.view.ui.FormatTextField;

public abstract class CryptOperation extends Operation {

	private static String[] inOutModes = new String[] { "Raw", "Hex" };

	protected String algorithm;
	protected FormatTextField ivTxt;
	protected FormatTextField keyTxt;

	protected JComboBox<String> cipherMode;
	protected JComboBox<String> inputMode;
	protected JComboBox<String> outputMode;
	protected JComboBox<String> paddings;

	public CryptOperation(String alogrithm) {
		super();
		this.algorithm = alogrithm;
		this.createMyUI();
	}

	protected byte[] crypt(byte[] input, int cipherMode, String algorithm, String mode, String padding)
			throws Exception {
		byte[] key = keyTxt.getText();
		byte[] iv = ivTxt.getText();

		SecretKeySpec secretKeySpec = new SecretKeySpec(key, algorithm);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		Cipher cipher = Cipher.getInstance(String.format("%s/%s/%s", algorithm, mode, padding));

        if( mode.equals("ECB") ) {
            cipher.init(cipherMode, secretKeySpec);
        } else {
            cipher.init(cipherMode, secretKeySpec, ivSpec);
        }

		byte[] encrypted = cipher.doFinal(input);

		return encrypted;
	}

	public void createMyUI() {
		this.ivTxt = new FormatTextField();
		this.addUIElement("IV", this.ivTxt);

		this.keyTxt = new FormatTextField();
		this.addUIElement("Key", this.keyTxt);
		CipherUtils utils = CipherUtils.getInstance();

		CipherInfo info = utils.getCipherInfo(this.algorithm);
		this.cipherMode = new JComboBox<>(info.getModes());
		this.addUIElement("Mode", this.cipherMode);

		this.paddings = new JComboBox<>(info.getPaddings());
		this.addUIElement("Padding", this.paddings);

		this.inputMode = new JComboBox<>(inOutModes);
		this.addUIElement("Input", this.inputMode);

		this.outputMode = new JComboBox<>(inOutModes);
		this.addUIElement("Output", this.outputMode);
	}

}
