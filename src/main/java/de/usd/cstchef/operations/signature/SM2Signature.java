package de.usd.cstchef.operations.signature;

import java.security.Signature;

import javax.swing.JComboBox;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "SM2 Signature", category = OperationCategory.SIGNATURE, description = "Create a SM2 signature")
public class SM2Signature extends KeystoreOperation {

    private static String[] inOutModes = new String[] { "Raw", "Hex", "Base64" };

    protected JComboBox<String> algos;
    protected JComboBox<String> inputMode;
    protected JComboBox<String> outputMode;

    public SM2Signature() {
        super();
        this.createMyUI();
    }

    protected ByteArray perform(ByteArray input) throws Exception {
        if( !this.keyAvailable.isSelected() )
            throw new IllegalArgumentException("No private key available.");

        String algo = (String)algos.getSelectedItem();
        Signature signature = Signature.getInstance(algo);

        String selectedInputMode = (String)inputMode.getSelectedItem();
        String selectedOutputMode = (String)outputMode.getSelectedItem();

        if( selectedInputMode.equals("Hex") )
            input = factory.createByteArray(Hex.decode(input.getBytes()));
        if( selectedInputMode.equals("Base64") )
            input = factory.createByteArray(Base64.decode(input.getBytes()));

        signature.initSign(this.selectedEntry.getPrivateKey());
        signature.update(input.getBytes());
        ByteArray result = factory.createByteArray(signature.sign());

        if( selectedOutputMode.equals("Hex") )
            result = factory.createByteArray(Hex.encode(result.getBytes()));
        if( selectedOutputMode.equals("Base64") )
            result = factory.createByteArray(Base64.encode(result.getBytes()));

        return result;
    }

    public void createMyUI() {

        super.createMyUI();
        SignatureUtils utils = SignatureUtils.getInstance();

        this.algos = new JComboBox<>(utils.getAlgos("SM2"));
        this.addUIElement("Padding", this.algos);

        this.inputMode = new JComboBox<>(inOutModes);
        this.addUIElement("Input", this.inputMode);

        this.outputMode = new JComboBox<>(inOutModes);
        this.addUIElement("Output", this.outputMode);
    }
}
