package de.usd.cstchef.operations.dataformat;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Set;

import javax.swing.JComboBox;
import org.bouncycastle.util.encoders.Hex;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "To Hex", category = OperationCategory.DATAFORMAT, description = "To hex")
public class ToHex extends Operation {

    static HashMap<String, Delimiter> delimiters = new HashMap<String, Delimiter>() {
        {
            put("None", new Delimiter(""));
            put("Space", new Delimiter(" "));
            put("Comma", new Delimiter(","));
            put("Colon", new Delimiter(":"));
            put("Semi-colon", new Delimiter(";"));
            put("Colon", new Delimiter(":"));
            put("Line feed", new Delimiter("\n"));
            put("CRLF", new Delimiter("\r\n"));
            put("0x", new Delimiter("0x", true));
            put("\\x", new Delimiter("\\x", true));
        }
    };

    private JComboBox<String> delimiterBox;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {
        String selectedKey = (String) this.delimiterBox.getSelectedItem();
        Delimiter delimiter = ToHex.delimiters.get(selectedKey);

        if (delimiter.value.length == 0) { // No delimiter
            return factory.createByteArray(Hex.encode(input.getBytes()));
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        if (input.length() > 0 && delimiter.writeAtStart) {
            out.write(delimiter.value);
        }

        for (int i = 0; i < input.length() - 1; i++) {
            out.write(Hex.encode(new byte[] { input.getByte(i) }));
            out.write(delimiter.value);
        }

        if (input.length() > 0) {
            out.write(Hex.encode(new byte[] { input.getByte(input.length() - 1) })); // wow
            if (delimiter.writeAtEnd) {
                out.write(delimiter.value);
            }
        }

        return factory.createByteArray(out.toByteArray());
    }

    @Override
    public void createUI() {
        Set<String> choices = ToHex.delimiters.keySet();
        delimiterBox = new JComboBox<String>(choices.toArray(new String[choices.size()]));
        delimiterBox.setSelectedIndex(0);

        this.addUIElement("Delimiter", delimiterBox);
    }

    public static class Delimiter {
        public byte[] value;
        public boolean writeAtStart;
        public boolean writeAtEnd;

        public Delimiter(String value) {
            this(value, false, false);
        }

        public Delimiter(String value, boolean writeAtStart) {
            this(value, writeAtStart, false);
        }

        public Delimiter(String value, boolean writeAtStart, boolean writeAtEnd) {
            this.value = value.getBytes();
            this.writeAtStart = writeAtStart;
            this.writeAtEnd = writeAtEnd;
        }
    }
}
