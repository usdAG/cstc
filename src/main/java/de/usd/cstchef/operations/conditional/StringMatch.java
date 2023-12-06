package de.usd.cstchef.operations.conditional;

import javax.swing.JCheckBox;

import burp.BurpExtender;
import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "String Match", category = OperationCategory.CONDITIONALS, description = "Skip if input matches")
public class StringMatch extends ConditionalOperation {

    private JCheckBox invert;
    private JCheckBox caseSensitive;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        
        ByteArray search = this.expr.getBytes();
        if( search.length() != input.length() ) {
            if( invert.isSelected() ) {
                this.setOperationSkip();
                this.setLaneSkip();
            } else {
                this.resetSkips();
            }
            return input;
        }

        MontoyaApi api = BurpUtils.getInstance().getApi();
        int start = api.utilities().byteUtils().indexOf(input.getBytes(), search.getBytes(), caseSensitive.isSelected(), 0, input.length());

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
