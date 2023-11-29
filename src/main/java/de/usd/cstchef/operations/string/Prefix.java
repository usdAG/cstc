package de.usd.cstchef.operations.string;

import java.io.ByteArrayOutputStream;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.FormatTextField;

@OperationInfos(name = "Prefix", category = OperationCategory.STRING, description = "Adds a prefix.")
public class Prefix extends Operation {

    private FormatTextField prefixTxt;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(prefixTxt.getText().getBytes());
        out.write(input.getBytes());

        return factory.createByteArray(out.toByteArray());
    }

    @Override
    public void createUI() {
        this.prefixTxt = new FormatTextField();
        this.addUIElement("Prefix", this.prefixTxt);
    }

}