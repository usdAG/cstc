package de.usd.cstchef.operations.setter;

import java.util.Arrays;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Line Setter", category = OperationCategory.SETTER, description = "Sets a line to the specified value.")
public class LineSetter extends SetterOperation {

    private JCheckBox append;
    private JComboBox<String> formatBox;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        int lineNumber;
        try {
            String number = getWhere();
            lineNumber = Integer.valueOf(number);
        } catch( Exception e ) {
            return input;
        }

        if( lineNumber <= 0 )
            return input;

        ByteArray newValue = getWhatBytes();
        ByteArray lineEndings = ByteArray.byteArray("\r\n");
        switch ((String) this.formatBox.getSelectedItem()) {
        case "\\r\\n":
            lineEndings = ByteArray.byteArray("\r\n");
            break;
        case "\\r":
            lineEndings = ByteArray.byteArray("\r");
            break;
        case "\\n":
            lineEndings = ByteArray.byteArray("\n");
            break;
        }

        MontoyaApi api = BurpUtils.getInstance().getApi();
        int length = input.length();

        int start = 0;
        int offset = 0;
        int counter = 0;
        while( counter < lineNumber - 1 ) {
            offset = api.utilities().byteUtils().indexOf(input.getBytes(), lineEndings.getBytes(), false, start, length);
            if( offset >= 0 ) {
                start = offset + lineEndings.length();
                counter++;
            } else {
                break;
            }
        }

        int end = api.utilities().byteUtils().indexOf(input.getBytes(), lineEndings.getBytes(), false, start, length);
        if( end < 0 )
            end = length;

        if( append.isSelected() ) {
            ByteArray value = ByteArray.byteArray(newValue.length() + lineEndings.length());
            System.arraycopy(lineEndings, 0, value, 0, lineEndings.length());
            System.arraycopy(newValue, 0, value, lineEndings.length(), newValue.length());
            return Utils.insertAtOffset(input, end, end, value);
        } else {
            return Utils.insertAtOffset(input, start, end, newValue);
        }
    }

    @Override
    public void createUI() {
        super.createUI();
        this.append = new JCheckBox("Insert below");
        this.append.setSelected(false);
        this.addUIElement(null, this.append, "checkbox1");

        this.formatBox = new JComboBox<>(new String[] {"\\r\\n", "\\r", "\\n"});
        this.formatBox.setSelectedItem("\\r\\n");
        this.addUIElement("Lineseperator", this.formatBox);
    }

}
