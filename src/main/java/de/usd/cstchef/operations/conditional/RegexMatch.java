package de.usd.cstchef.operations.conditional;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JCheckBox;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Regex Match", category = OperationCategory.CONDITIONALS, description = "Skip if regex matches")
public class RegexMatch extends ConditionalOperation {

    private JCheckBox invert;
    private JCheckBox find;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        Pattern p = Pattern.compile(this.expr.getText());
        Matcher m = p.matcher(input.toString());

        boolean condition = false;
        if( find.isSelected() ) {
            condition = m.find();
        } else {
            condition = m.matches();
        }

        if( condition ^ invert.isSelected() ) {
            this.setOperationSkip();
            this.setLaneSkip();
        } else {
            this.resetSkips();
        }

        return input;
    }

    @Override
    public void createUI() {
        super.createUI();

        this.invert = new JCheckBox();
        this.addUIElement("Invert Match", this.invert);

        this.find = new JCheckBox();
        this.addUIElement("Find anywhere", this.find);
    }

}
