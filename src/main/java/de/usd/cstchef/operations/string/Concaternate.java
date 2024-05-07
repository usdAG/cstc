package de.usd.cstchef.operations.string;

import de.usd.cstchef.VariableStore;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextArea;


@OperationInfos(name = "Concaternate", category = OperationCategory.STRING, description = "Concaternate multiple string values or variables. Separate multiple strings or variables with ';'.")
public class Concaternate extends Operation {
    
    private VariableTextArea text;

    @Override
    protected byte[] perform(byte[] input) throws Exception {

        String[] components = text.getText().split(";");
        String trimed;
        byte[][] value = new byte[components.length][];
        for (int i = 0; i < components.length; i++) {
            trimed = components[i].trim();

            if (trimed.startsWith("$")) {
                value[i] = VariableStore.getInstance().getVariable(trimed);
            } else {
                value[i] = trimed.getBytes();
            }
        }

        return flatten_array(value);
    }

    public void createUI() {
        this.text = new VariableTextArea();
        this.addUIElement("Values to concaternate", this.text);
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
