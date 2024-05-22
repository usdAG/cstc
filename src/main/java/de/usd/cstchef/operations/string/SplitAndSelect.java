package de.usd.cstchef.operations.string;

import org.bouncycastle.util.Arrays;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "Split and Select", category = OperationCategory.STRING, description = "Split input and select one item.")
public class SplitAndSelect extends Operation {

    private VariableTextField item;
    private VariableTextField delim;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        ByteArray delimmiter = delim.getBytes();

        int itemNumber = 0;
        try {
            String itemValue = item.getText();
            itemNumber = Integer.valueOf(itemValue);
        } catch(Exception e) {
            return input;
        }

        if( itemNumber < 0 )
            return input;

        MontoyaApi api = BurpUtils.getInstance().getApi();
        int length = input.length();

        int start = 0;
        int offset = 0;
        int counter = 0;
        while( counter < itemNumber ) {
            offset = api.utilities().byteUtils().indexOf(input.getBytes(), delimmiter.getBytes(), false, start, length);
            if( offset >= 0 ) {
                start = offset + delimmiter.length();
                counter++;
            } else {
                break;
            }
        }

        int end = api.utilities().byteUtils().indexOf(input.getBytes(), delimmiter.getBytes(), false, start, length);
        if( end < 0 )
            end = length;

        ByteArray result = BurpUtils.subArray(input, start, end);
        return result;
    }

    @Override
    public void createUI() {
        this.delim = new VariableTextField();
        this.addUIElement("Delimiter", this.delim);
        this.item = new VariableTextField();
        this.addUIElement("Item number", this.item);
    }
}
