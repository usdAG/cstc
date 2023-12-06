package de.usd.cstchef.operations.datetime;

import javax.swing.JCheckBox;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Unix Timestamp", category = OperationCategory.DATES, description = "Returnes the current unix timestamp.")
public class UnixTimestamp extends Operation {

    private JCheckBox milliBox;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        long timestamp = 0;
        if (milliBox.isSelected()) {
            timestamp = System.currentTimeMillis();
        }
        else {
            timestamp = System.currentTimeMillis() / 1000L;
        }
        return factory.createByteArray(String.valueOf(timestamp));
    }

    public void createUI() {
        this.milliBox = new JCheckBox();
        this.addUIElement("Milliseconds", this.milliBox);
    }

}
