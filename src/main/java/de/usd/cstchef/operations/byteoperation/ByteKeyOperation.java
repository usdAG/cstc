package de.usd.cstchef.operations.byteoperation;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.view.ui.FormatTextField;

public abstract class ByteKeyOperation extends Operation  {

    private FormatTextField inputTxt;

    public void createUI() {
        this.inputTxt = new FormatTextField();
        this.addUIElement("Key", inputTxt);
    }

    @Override
    protected byte[] perform(byte[] input) throws Exception {

        byte[] result = new byte[input.length];
        byte[] key = this.inputTxt.getText();

        if (key.length == 0) {
            return input;
        }

        int keyCounter = 0;
        for (int i = 0; i < input.length; i++) {
            byte var = key[keyCounter];
            keyCounter = (keyCounter + 1) % key.length;
            result[i] = calculate(input[i], var);
        }

        return result;
    }

    protected abstract byte calculate(byte input, byte var);

}
