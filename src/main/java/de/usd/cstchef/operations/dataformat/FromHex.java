package de.usd.cstchef.operations.dataformat;

import java.util.Set;

import javax.swing.JComboBox;
import org.bouncycastle.util.encoders.Hex;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.dataformat.ToHex.Delimiter;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "From Hex", category = OperationCategory.DATAFORMAT, description = "From hex")
public class FromHex extends Operation {

    private JComboBox<String> delimiterBox;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        String selectedKey = (String) this.delimiterBox.getSelectedItem();
        Delimiter delimiter = ToHex.delimiters.get(selectedKey);

        if (delimiter.value.length == 0) { // No delimiter
            return ByteArray.byteArray(Hex.decode(input.getBytes()));
        }

        String delimiterStr = new String(delimiter.value);
        String inputStr = input.toString();
        inputStr = inputStr.replace(delimiterStr, "");

        return ByteArray.byteArray(Hex.decode(inputStr.getBytes()));
    }

    @Override
    public void createUI() {
        Set<String> choices = ToHex.delimiters.keySet();
        delimiterBox = new JComboBox<String>(choices.toArray(new String[choices.size()]));
        delimiterBox.setSelectedIndex(0);

        this.addUIElement("Delimiter", delimiterBox);
    }

}
