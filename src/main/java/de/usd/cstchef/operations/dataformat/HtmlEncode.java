package de.usd.cstchef.operations.dataformat;

import java.io.ByteArrayOutputStream;

import javax.swing.JCheckBox;

import org.apache.commons.text.StringEscapeUtils;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTML Encode", category = OperationCategory.DATAFORMAT, description = "HTML Encode")
public class HtmlEncode extends Operation {

    private JCheckBox checkbox;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        ByteArray result = null;
        if( checkbox.isSelected() ) {

            ByteArray delimiter = ByteArray.byteArray("&#");
            ByteArray closer = ByteArray.byteArray(";");
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            out.write(delimiter.getBytes());
            for (int i = 0; i < input.length() - 1; i++) {
                out.write(String.valueOf(Byte.toUnsignedInt(input.getByte(i))).getBytes());
                out.write(closer.getBytes());
                out.write(delimiter.getBytes());
            }

            out.write(String.valueOf(Byte.toUnsignedInt(input.getByte(input.length() - 1))).getBytes());
            out.write(closer.getBytes());
            result = ByteArray.byteArray(out.toByteArray());

        } else {
            String tmp = input.toString();
            tmp = StringEscapeUtils.escapeHtml4(tmp);
            result = ByteArray.byteArray(tmp);
        }

        return result;
    }

    @Override
    public void createUI() {
        this.checkbox = new JCheckBox("Encode all");
        this.checkbox.setSelected(false);
        this.addUIElement(null, this.checkbox, "checkbox1");
    }
}
