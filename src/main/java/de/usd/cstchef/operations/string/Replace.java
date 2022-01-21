package de.usd.cstchef.operations.string;

import javax.swing.JCheckBox;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextArea;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "Replace", category = OperationCategory.STRING, description = "Uses a regular expression to replace all occurences. Has side effect on binary content due to String Encoding.")
public class Replace extends Operation {

    private JCheckBox checkbox;
    private VariableTextField exptTxt;
    private VariableTextArea replacementTxt;

    @Override
    protected byte[] perform(byte[] input) throws Exception {

        byte[] result = null;
        if( checkbox.isSelected() ) {
            String inputStr = new String(input);
            result = inputStr.replaceAll(exptTxt.getText(), replacementTxt.getText()).getBytes();
        } else {
            IBurpExtenderCallbacks cbs = BurpUtils.getInstance().getCallbacks();
            IExtensionHelpers helpers = cbs.getHelpers();

            int start = helpers.indexOf(input, exptTxt.getBytes(), true, 0, input.length);

            if(start < 0)
                return input;

            byte[] replaced = exptTxt.getBytes();
            byte[] replacement = replacementTxt.getBytes();

            byte[] newRequest = new byte[input.length + replacement.length - replaced.length];
            System.arraycopy(input, 0, newRequest, 0, start);
            System.arraycopy(replacement, 0, newRequest, start, replacement.length);
            System.arraycopy(input, start + replaced.length, newRequest, start + replacement.length, input.length - replaced.length - start);

            result = newRequest;
        }

        return result;
    }

    @Override
    public void createUI() {
        this.exptTxt = new VariableTextField();
        this.addUIElement("Expr", this.exptTxt);

        this.checkbox = new JCheckBox("Regex");
        this.checkbox.setSelected(false);
        this.addUIElement(null, this.checkbox, "checkbox1");

        this.replacementTxt = new VariableTextArea();
        this.addUIElement("Value", this.replacementTxt);
    }

}
