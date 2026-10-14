package de.usd.cstchef.operations.hashing;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JComboBox;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.FormatTextField;

@OperationInfos(name = "HMAC", category = OperationCategory.HASHING, description = "Creates an HMAC with the chosen hashing function.")
public class Hmac extends Operation {

    private static final String[] outModes = new String[] { "Raw", "Hex", "Base64" };
    
    private FormatTextField keyTxt;
    private JComboBox<String> hashAlgoBox;
    private JComboBox<String> outputMode;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        byte[] key = this.keyTxt.getText().getBytes();
        String algo = "Hmac" + (String) hashAlgoBox.getSelectedItem();
        SecretKeySpec signingKey = new SecretKeySpec(key, algo);
        Mac mac = Mac.getInstance(algo);
        mac.init(signingKey);
        byte[] hash = mac.doFinal(input.getBytes());
        
        String selectedOutputMode = (String)outputMode.getSelectedItem();
        if( selectedOutputMode.equals("Hex") )
            hash = Hex.encode(hash);
        if( selectedOutputMode.equals("Base64") )
            hash = Base64.encode(hash);
        
        return factory.createByteArray(hash);
    }

    @Override
    public void createUI() {
        String[] algorithms = { "MD5", "SHA1", "SHA256", "SHA224", "SHA384", "SHA512", "GOST3411" };
        this.hashAlgoBox = new JComboBox<>(algorithms);
        this.addUIElement("Hashing function", this.hashAlgoBox);

        this.keyTxt = new FormatTextField();
        this.addUIElement("Key", this.keyTxt);

        this.outputMode = new JComboBox<>(outModes);
        this.addUIElement("Output", this.outputMode);
    }

}
