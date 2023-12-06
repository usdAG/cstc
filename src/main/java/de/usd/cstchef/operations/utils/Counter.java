package de.usd.cstchef.operations.utils;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import javax.swing.JTextField;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.VariableStore;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Counter", category = OperationCategory.UTILS, description = "Increments a counter and stores it in a variable.")
public class Counter extends Operation {

    private JTextField varNameTxt;
    private JTextField startValueTxt;
    private JTextField stepSizeTxt;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        String varName = this.varNameTxt.getText().trim();
        long value;
        long stepSize = Long.valueOf(this.stepSizeTxt.getText());
        long startValue = Long.valueOf(this.startValueTxt.getText());
        if (VariableStore.getInstance().getVariable(varName) == null) {
            value = startValue;
        } else {
            ByteArray currentValue = VariableStore.getInstance().getVariable(varName);
            try {
                value = Long.parseLong(currentValue.toString());
            } catch (NumberFormatException e) {
                this.setErrorMessage(e);
                value = startValue;
            }
        }
        String storeValue = Long.toString(value + stepSize);
        VariableStore.getInstance().setVariable(varName, factory.createByteArray(storeValue));
        return input;
    }

    public void createUI() {
        this.varNameTxt = new JTextField();
        this.addUIElement("Variable Name", this.varNameTxt);

        this.startValueTxt = new JTextField();
        this.startValueTxt.setText("0");
        this.addUIElement("Start Value", this.startValueTxt);

        this.stepSizeTxt = new JTextField();
        this.stepSizeTxt.setText("1");
        this.addUIElement("Step Size", this.stepSizeTxt);
    }

}
