package de.usd.cstchef.operations.conditional;

import javax.swing.JCheckBox;

import burp.BurpExtender;
import burp.api.montoya.MontoyaApi;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "String Contains", category = OperationCategory.CONDITIONALS, description = "Skip if input contains")
public class StringContains extends ConditionalOperation {

    private JCheckBox invert;
    private JCheckBox caseSensitive;

    @Override
    protected byte[] perform(byte[] input) throws Exception {

        MontoyaApi api = BurpExtender.getApi();
        int start = api.utilities().byteUtils().indexOf(input, this.expr.getBytes(), caseSensitive.isSelected(), 0, input.length);
        api.utilities().byteUtils().indexOf(input, this.expr.getBytes(), caseSensitive.isSelected(), 0, input.length);
        if( (start >= 0) ^ invert.isSelected() ) {
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

        this.caseSensitive = new JCheckBox();
        this.addUIElement("Case Sensitive", this.caseSensitive);
    }

}
