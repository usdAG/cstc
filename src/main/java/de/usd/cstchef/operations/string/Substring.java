package de.usd.cstchef.operations.string;

import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;

import org.bouncycastle.util.Arrays;

import burp.BurpUtils;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Substring", category = OperationCategory.STRING, description = "Extracts a substring.")
public class Substring extends Operation {

    private JSpinner startSpinner;
    private JSpinner endSpinner;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        int start = (int) startSpinner.getValue();
        int end = (int) endSpinner.getValue();

        if(input.length() + start < 0) throw new IllegalArgumentException("Start index out of bounds for input length " + input.length() + ".");
        if(end > input.length()) throw new IllegalArgumentException("End index out of bounds for input length " + input.length() + ".");

        ByteArray slice = BurpUtils.subArray(input, start, end);
        return slice;
    }

    @Override
    public void createUI() {
        SpinnerNumberModel startIndexModel = new SpinnerNumberModel(0, 0, Integer.MAX_VALUE, 1);
        this.startSpinner = new JSpinner(startIndexModel);
        this.addUIElement("Start", this.startSpinner);

        SpinnerNumberModel endIndexModel = new SpinnerNumberModel(0, 0, Integer.MAX_VALUE, 1);
        this.endSpinner = new JSpinner(endIndexModel);
        this.addUIElement("End", this.endSpinner);
    }

}
