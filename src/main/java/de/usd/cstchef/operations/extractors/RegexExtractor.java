package de.usd.cstchef.operations.extractors;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JComboBox;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "Regex", category = OperationCategory.EXTRACTORS, description = "Extracts using a regex.")
public class RegexExtractor extends Operation {

    private static String LIST_MATCHES = "List matches";
    private static String LIST_GROUPS = "List capture groups";

    private VariableTextField regexTxt;
    private JComboBox<String> outputBox;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        Pattern p = Pattern.compile(this.regexTxt.getText());
        Matcher m = p.matcher(input.toString());
        String outputType = (String) this.outputBox.getSelectedItem();

        StringBuffer buf = new StringBuffer();

        while (m.find()) {
            if (outputType.equals(LIST_MATCHES)) {
                buf.append(m.group()).append("\n");
            } else {
                for (int i = 1; i <= m.groupCount(); i++) {
                    buf.append(m.group(i)).append("\n");
                }
            }
        }

        if( buf.length() > 0 )
            buf.setLength(buf.length() - 1);

        return factory.createByteArray(buf.toString());
    }

    @Override
    public void createUI() {
        this.regexTxt = new VariableTextField();
        this.addUIElement("Regex", this.regexTxt);

        this.outputBox = new JComboBox<>(new String[] { LIST_MATCHES, LIST_GROUPS });
        this.addUIElement("Output format", this.outputBox);
    }
}
