package de.usd.cstchef.operations.signature;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.swing.JComboBox;

import org.bouncycastle.util.encoders.Hex;

import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.StringReader;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextArea;

@OperationInfos(name = "EdDSA Signature", category = OperationCategory.SIGNATURE, description = "Create an EdDSA signature (Ed25519, Ed448)")
public class EdDsaSignature extends KeystoreOperation {

    private VariableTextArea privateKeyTextArea;

    private JComboBox<String> typeComboBox;
    private JComboBox<String> variantComboBox;

    private static String[] variants = new String[] { "Ed25519", "Ed448" };
    private static String[] inOutModes = new String[] { "Raw", "Hex", "Base64" };

    protected JComboBox<String> algos;
    protected JComboBox<String> inputMode;
    protected JComboBox<String> outputMode;

    private String lastSelection = "PEM";

    public EdDsaSignature() {
        super();
        this.createUIForPEM();
    }

    protected ByteArray perform(ByteArray input) throws Exception {

        if (typeComboBox.getSelectedItem().equals("PEM")) {
            String privateKeyString = this.privateKeyTextArea.getBytes().toString();

            if (privateKeyString.length() == 0) {
                throw new IllegalArgumentException("No private key available.");
            }

            StringBuilder privateKeyLines = new StringBuilder();
            BufferedReader buffRead = new BufferedReader(new StringReader(privateKeyString));

            String line;
            while ((line = buffRead.readLine()) != null) {
                privateKeyLines.append(line);
            }

            String privateKeyPEM = privateKeyLines.toString();
            privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----", "");
            privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
            privateKeyPEM = privateKeyPEM.replaceAll("\\s+", "");

            String variant = (String) variantComboBox.getSelectedItem();
            byte[] pkcs8Bytes = Base64.getDecoder().decode(privateKeyPEM);
            PrivateKey privateKey = KeyFactory.getInstance(variant)
                    .generatePrivate(new PKCS8EncodedKeySpec(pkcs8Bytes));

            Signature sig = Signature.getInstance(variant);
            sig.initSign(privateKey);
            sig.update(input.getBytes());

            return factory.createByteArray(sig.sign());
        }
        else if (typeComboBox.getSelectedItem().equals("KeyStore")) {
            if (!this.keyAvailable.isSelected())
                throw new IllegalArgumentException("No private key available.");

            String algo = (String) algos.getSelectedItem();
            Signature signature = Signature.getInstance(algo);

            String selectedInputMode = (String) inputMode.getSelectedItem();
            String selectedOutputMode = (String) outputMode.getSelectedItem();

            if (selectedInputMode.equals("Hex"))
                input = factory.createByteArray(Hex.decode(input.getBytes()));
            if (selectedInputMode.equals("Base64"))
                input = factory.createByteArray(Base64.getDecoder().decode(input.getBytes()));

            signature.initSign(this.selectedEntry.getPrivateKey());
            signature.update(input.getBytes());
            ByteArray result = factory.createByteArray(signature.sign());

            if (selectedOutputMode.equals("Hex"))
                result = factory.createByteArray(Hex.encode(result.getBytes()));
            if (selectedOutputMode.equals("Base64"))
                result = factory.createByteArray(Base64.getEncoder().encode(result.getBytes()));

            return result;
        }
        else {
            return factory.createByteArray("");
        }
    }

    @Override
    public void createUI() {
        this.typeComboBox = new JComboBox<String>();
        this.typeComboBox.addItem("PEM");
        this.typeComboBox.addItem("KeyStore");

        ActionListener comboBoxActionListener = new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                /* The method should only run if the ActionEvent was triggered by the user in the UI (e.getModifiers() == 16).
                 * Not, for example, when loading a recipe (e.getModifiers() == 0)
                 */
                if (e.getModifiers() == 16) {
                    switch ((String) typeComboBox.getSelectedItem()) {
                        case "PEM":
                            if (!lastSelection.equals("PEM")) {
                                clearUI();
                                createUIForPEM();
                            }
                            break;
                        case "KeyStore":
                            if (!lastSelection.equals("KeyStore")) {
                                clearUI();
                                createMyUI();
                            }
                            break;
                    }
                    lastSelection = (String) typeComboBox.getSelectedItem();
                    validate();
                    repaint();
                    updateStepPanel();
                }
            }

        };

        typeComboBox.addActionListener(comboBoxActionListener);
        this.addUIElement("Input Type", typeComboBox);
    }

    public void createMyUI() {
        super.createMyUI();
        SignatureUtils utils = SignatureUtils.getInstance();

        this.algos = new JComboBox<>(utils.getAlgos("Ed"));
        this.addUIElement("Algorithm", this.algos);

        this.inputMode = new JComboBox<>(inOutModes);
        this.addUIElement("Input", this.inputMode);

        this.outputMode = new JComboBox<>(inOutModes);
        this.addUIElement("Output", this.outputMode);
    }

    private void clearUI() {
        Iterator<String> iterator = this.getUIElements().keySet().iterator();

        while (iterator.hasNext()) {
            String key = iterator.next();
            if (!key.equals("Input Type")) {
                iterator.remove();
                this.clearContentBox(2);
            }
        }
        this.validate();
        this.repaint();
    }

    private void createUIForPEM() {
        this.variantComboBox = new JComboBox<>(variants);
        this.addUIElement("Variant", this.variantComboBox);

        this.privateKeyTextArea = new VariableTextArea();
        this.addUIElement("Private Key", this.privateKeyTextArea);
    }

    public void updateStepPanel() {
        super.updateStepPanel();
    }

    @Override
    public void load(Map<String, Object> parameters) {
        if (parameters.get("Input Type") == null || parameters.get("Input Type").equals("KeyStore")) {
            this.clearUI();
            this.createMyUI();
        }
        else if (parameters.get("Input Type").equals("PEM")) {
            this.clearUI();
            this.createUIForPEM();
        }
        super.load(parameters);
    }
}
