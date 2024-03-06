package de.usd.cstchef.operations.byteoperation;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.view.ui.FormatTextField;

public abstract class ByteKeyOperation extends Operation  {

    private FormatTextField inputTxt;

    public void createUI() {
        this.inputTxt = new FormatTextField();
        this.addUIElement("Key", inputTxt);
    }

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        ByteArray result = factory.createByteArray(input.length());
        ByteArray key = this.inputTxt.getText();

        if (key.length() == 0) {
            return input;
        }

        int keyCounter = 0;
        for (int i = 0; i < input.length(); i++) {
            byte var = key.getByte(keyCounter);
            keyCounter = (keyCounter + 1) % key.length();
            result.setByte(i, calculate(input.getByte(i), var));
        }

        return result;
    }

    protected abstract byte calculate(byte input, byte var);

}
