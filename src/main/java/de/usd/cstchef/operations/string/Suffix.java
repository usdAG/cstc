package de.usd.cstchef.operations.string;

import java.io.ByteArrayOutputStream;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.FormatTextField;

@OperationInfos(name = "Suffix", category = OperationCategory.STRING, description = "Adds a suffix.")
public class Suffix extends Operation {

    private FormatTextField  suffixTxt;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(input.getBytes());
        out.write(suffixTxt.getText().getBytes());

        return factory.createByteArray(out.toByteArray());
    }

    @Override
    public void createUI() {
        this.suffixTxt = new FormatTextField ();
        this.addUIElement("Suffix", this.suffixTxt);
    }

}