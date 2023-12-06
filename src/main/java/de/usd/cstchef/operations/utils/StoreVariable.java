package de.usd.cstchef.operations.utils;

import javax.swing.JTextField;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.VariableStore;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Store Variable", category = OperationCategory.UTILS, description = "Stores variables to be retrieved later.")
public class StoreVariable extends Operation {

    private JTextField varNameTxt;
    private String oldVarName;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        String newVarName = this.varNameTxt.getText().trim();
        VariableStore store = VariableStore.getInstance();
        // remove old variable from hashmap
        if (!newVarName.equals(oldVarName)) {
            store.removeVariable(this.oldVarName);
            this.oldVarName = newVarName;
        }

        if (!newVarName.isEmpty()) {
            store.setVariable(newVarName, input);
        }

        return input;
    }

    public void createUI() {
        this.varNameTxt = new JTextField();
        this.addUIElement("Variable name", this.varNameTxt);
    }

    @Override
    public void onRemove() {
        VariableStore.getInstance().removeVariable(this.oldVarName);
    }

}
