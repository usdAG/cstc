package de.usd.cstchef.operations.dataformat;

import javax.swing.JCheckBox;

import burp.BurpUtils;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.utilities.HtmlEncoding;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTML Encode", category = OperationCategory.DATAFORMAT, description = "HTML Encode")
public class HtmlEncode extends Operation {

    private JCheckBox checkbox;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        String encodedInput;

        if(checkbox.isSelected()) {
            encodedInput = BurpUtils.getInstance().getApi().utilities().htmlUtils().encode(input.toString(), HtmlEncoding.ALL_CHARACTERS);
        }
        else {
            encodedInput = BurpUtils.getInstance().getApi().utilities().htmlUtils().encode(input.toString(), HtmlEncoding.STANDARD);
        }

        return factory.createByteArray(encodedInput);
    }

    @Override
    public void createUI() {
        this.checkbox = new JCheckBox("Encode all");
        this.checkbox.setSelected(false);
        this.addUIElement(null, this.checkbox, "checkbox1");
    }
}
