package de.usd.cstchef.operations.string;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextArea;

@OperationInfos(name = "Static string", category = OperationCategory.STRING, description = "Returns the defined string.")
public class StaticString extends Operation {

    private VariableTextArea stringTxt;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        return this.stringTxt.getBytes();
    }

    @Override
    public void createUI() {
        this.stringTxt = new VariableTextArea();
        this.addUIElement("Value", this.stringTxt);
    }

}
