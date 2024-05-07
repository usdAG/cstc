package de.usd.cstchef.operations.utils;

import javax.swing.JCheckBox;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.FormatTextField;

@OperationInfos(name = "Set if Empty", category = OperationCategory.UTILS, description = "Sets a value if the input is empty.")
public class SetIfEmpty extends Operation {

    private FormatTextField value;
    private JCheckBox checkbox;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        ByteArray valueToSet = value.getText();
        if( input.length() == 0 ) {
            return valueToSet;
        }

        if( !checkbox.isSelected() )
            return input;

        int i = 0;
        while( i < input.length() ) {
            if( input.getByte(i) != 32 ) {
                return input;
            }
            i++;
        }

        return valueToSet;
    }

    public void createUI() {
        this.value = new FormatTextField();
        this.addUIElement("Value to set", this.value);

        this.checkbox = new JCheckBox("Space is empty");
        this.checkbox.setSelected(false);
        this.addUIElement(null, this.checkbox, "checkbox1");
    }
}
