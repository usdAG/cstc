package de.usd.cstchef.operations.utils;

import javax.swing.JTextField;

import de.usd.cstchef.VariableStore;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Get Variable", category = OperationCategory.UTILS, description = "Retrives a stored variable.")
public class GetVariable extends Operation {

    private JTextField varNameTxt;
    private JTextField defaultTxt;

    @Override
    protected byte[] perform(byte[] input) throws Exception {
        String varName = this.varNameTxt.getText().trim();
        byte[] var = VariableStore.getInstance().getVariable(varName);
        return var == null ? this.defaultTxt.getText().getBytes() : var;
    }

    public void createUI() {
        this.varNameTxt = new JTextField();
        this.addUIElement("Variable name", this.varNameTxt);

        this.defaultTxt = new JTextField();
        this.addUIElement("Default value", this.defaultTxt);
    }

}
