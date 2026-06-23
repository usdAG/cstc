package de.usd.cstchef.operations.dataformat;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Set;

import javax.swing.JComboBox;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.dataformat.ToHex.Delimiter;

@OperationInfos(name = "To Decimal", category = OperationCategory.DATAFORMAT, description = "Converts the input to an integer array.")
public class ToDecimal extends Operation {

    static HashMap<String, Delimiter> delimiters = new HashMap<String, Delimiter>() {
        {
            put("Space", new Delimiter(" "));
            put("Comma", new Delimiter(","));
            put("Semi-colon", new Delimiter(";"));
            put("Colon", new Delimiter(":"));
            put("Line feed", new Delimiter("\n"));
            put("CRLF", new Delimiter("\r\n"));
        }
    };

    private JComboBox<String> delimiterBox;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        String selectedKey = (String) this.delimiterBox.getSelectedItem();
        Delimiter delimiter = ToHex.delimiters.get(selectedKey);
        String delimString = new String(delimiter.value, StandardCharsets.UTF_8);

        byte[] inputBytes = input.getBytes();
        StringBuilder output = new StringBuilder();

        if (input.length() > 0 && delimiter.writeAtStart) {
            output.append(delimString);
        }

        for (int i = 0; i < inputBytes.length - 1; i++) {
            output.append(inputBytes[i] & 0xFF);
            output.append(delimString);
        }

        if (input.length() > 0) {
            output.append(inputBytes[inputBytes.length - 1] & 0xFF);
            if (delimiter.writeAtEnd) {
                output.append(delimString);
            }
        }

        return factory.createByteArray(output.toString());
    }

    @Override
    public void createUI() {
        Set<String> choices = ToDecimal.delimiters.keySet();
        delimiterBox = new JComboBox<String>(choices.toArray(new String[choices.size()]));
        delimiterBox.setSelectedIndex(0);

        this.addUIElement("Delimiter", delimiterBox);
    }
}

