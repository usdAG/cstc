package de.usd.cstchef.operations.string;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.VariableStore;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextArea;
import de.usd.cstchef.view.ui.VariableTextField;


@OperationInfos(name = "Concatenate", category = OperationCategory.STRING, description = "Concatenate CSTC Input and/or your own. \"$input\" to work with CSTC Input.")
public class Concatenate extends Operation {
    
    protected VariableTextArea text;
    protected VariableTextField delimiter;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String delim = delimiter.getText();
        VariableStore.getInstance().setVariable("input", input);

        String[] components = text.getText().split(delim);
        String trimed;
        byte[][] value = new byte[components.length][];
        for (int i = 0; i < components.length; i++) {
            trimed = components[i].trim();

            if (trimed.startsWith("$")) {
                value[i] = VariableStore.getInstance().getVariable(trimed).getBytes();
            } else {
                value[i] = trimed.getBytes();
            }
        }

        return factory.createByteArray(flatten_array(value));
    }

    public void createUI() {
        this.text = new VariableTextArea();
        this.addUIElement("Strings", this.text);
        this.delimiter = new VariableTextField();
        this.addUIElement("Delimiter", this.delimiter);
    }

    private byte[] flatten_array(byte[][] arrays){

        // Calculate the total length of the concatenated array
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }

        // Create the concatenated array
        byte[] result = new byte[totalLength];
        int currentIndex = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, currentIndex, array.length);
            currentIndex += array.length;
        }

        return result;
    }

}
