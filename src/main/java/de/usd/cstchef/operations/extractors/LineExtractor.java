package de.usd.cstchef.operations.extractors;

import javax.swing.JComboBox;

import org.bouncycastle.util.Arrays;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "Line Extractor", category = OperationCategory.EXTRACTORS, description = "Extracts the specified line number.")
public class LineExtractor extends Operation {

    private VariableTextField lineNumberField;
    private JComboBox<String> formatBox;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        int lineNumber = 0;
        try {
            String number = lineNumberField.getText();
            lineNumber = Integer.valueOf(number);
        } catch(Exception e) {
            return input;
        }

        if( lineNumber <= 0 )
            return input;

        byte[] lineEndings = "\r\n".getBytes();
        switch ((String) this.formatBox.getSelectedItem()) {
        case "\\r\\n":
            lineEndings = "\r\n".getBytes();
            break;
        case "\\r":
            lineEndings = "\r".getBytes();
            break;
        case "\\n":
            lineEndings = "\n".getBytes();
            break;
        }

        MontoyaApi api = BurpUtils.getInstance().getApi();
        int length = input.length();

        int start = 0;
        int offset = 0;
        int counter = 0;
        while( counter < lineNumber - 1 ) {
            offset = api.utilities().byteUtils().indexOf(input.getBytes(), lineEndings, false, start, length);
            if( offset >= 0 ) {
                start = offset + lineEndings.length;
                counter++;
            } else {
                break;
            }
        }

        int end = api.utilities().byteUtils().indexOf(input.getBytes(), lineEndings, false, start, length);
        if( end < 0 )
            end = length;

        ByteArray result = BurpUtils.subArray(input, start, end);
        return result;
    }

    @Override
    public void createUI() {
        this.lineNumberField = new VariableTextField();
        this.addUIElement("Name", this.lineNumberField);
        this.formatBox = new JComboBox<>(new String[] {"\\r\\n", "\\r", "\\n"});
        this.formatBox.setSelectedItem("\\r\\n");
        this.addUIElement("Lineseperator", this.formatBox);
    }

}
