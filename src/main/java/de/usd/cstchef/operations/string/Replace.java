package de.usd.cstchef.operations.string;

import javax.swing.JCheckBox;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
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
    protected ByteArray perform(ByteArray input) throws Exception {

        ByteArray result = null;
        if( checkbox.isSelected() ) {
            String inputStr = input.toString();
            result = factory.createByteArray(inputStr.replaceAll(exptTxt.getText(), replacementTxt.getText()));
        } else {

            MontoyaApi api = BurpUtils.getInstance().getApi();
            int start = api.utilities().byteUtils().indexOf(input.getBytes(), exptTxt.getBytes().getBytes(), true, 0, input.length());

            if(start < 0)
                return input;

            ByteArray replaced = exptTxt.getBytes();
            ByteArray replacement = replacementTxt.getBytes();

            ByteArray newRequest = input.subArray(0, start).withAppended(replacement).withAppended(input.subArray(start + replaced.length(), input.length()));

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
