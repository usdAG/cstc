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

@OperationInfos(name = "From Decimal", category = OperationCategory.DATAFORMAT, description = "Converts an integer array back into its raw form.")
public class FromDecimal extends Operation {

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

        if(input.length() == 0) {
            return input;
        }

        String selectedKey = (String) this.delimiterBox.getSelectedItem();
        Delimiter delimiter = ToHex.delimiters.get(selectedKey);
        String delimString = new String(delimiter.value, StandardCharsets.UTF_8);

        String[] parts = input.toString().trim().split(delimString);

        byte[] decodedBytes = new byte[parts.length];

        for (int i = 0; i < parts.length; i++) {
            try {
                decodedBytes[i] = (byte) Integer.parseInt(parts[i]);
            }
            catch(NumberFormatException e) {
                if(e.getMessage().split("\\s+")[0].equals("For")) {
                    if(parts[i].length() < 100) {
                        throw new IllegalArgumentException("Cannot parse string \"" + parts[i] + "\" to an integer.");
                    }
                    else {
                        throw new IllegalArgumentException("Cannot parse parts of the string to an integer.");
                    }
                }
                else {
                    throw new IllegalArgumentException("Please ensure that the input only contains parsable integers and delimiters.");
                }
            }
        }

        String output = new String(decodedBytes, StandardCharsets.UTF_8);

        return factory.createByteArray(output);
    }

    @Override
    public void createUI() {
        Set<String> choices = FromDecimal.delimiters.keySet();
        delimiterBox = new JComboBox<String>(choices.toArray(new String[choices.size()]));
        delimiterBox.setSelectedIndex(0);

        this.addUIElement("Delimiter", delimiterBox);
    }
}
