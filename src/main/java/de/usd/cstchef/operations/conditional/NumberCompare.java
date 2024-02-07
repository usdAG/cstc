package de.usd.cstchef.operations.conditional;

import javax.swing.JComboBox;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Number Compare", category = OperationCategory.CONDITIONALS, description = "Skip if evaluates to true")
public class NumberCompare extends ConditionalOperation {

    private JComboBox<String> operationBox;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        Double inputNumber;
        Double userNumber;

        try {
            String tmp = input.toString();
            inputNumber = Double.valueOf(tmp);
            userNumber = Double.valueOf(this.expr.getText());
        } catch( Exception e ) {
            throw new IllegalArgumentException("Input is not a number.");
        }

        boolean condition = false;
        switch ((String)this.operationBox.getSelectedItem()) {
        case "equal":
            if( inputNumber.compareTo(userNumber) == 0 )
                condition = true;
            break;
        case "not equal":
            if( inputNumber.compareTo(userNumber) != 0 )
                condition = true;
            break;
        case "greater":
            if( inputNumber < userNumber )
                condition = true;
            break;
        case "lower":
            if( inputNumber > userNumber )
                condition = true;
            break;
        case "greater equal":
            if( inputNumber <= userNumber )
                condition = true;
            break;
        case "lower equal":
            if( inputNumber >= userNumber )
                condition = true;
            break;
        }

        if( condition ) {
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
        this.operationBox = new JComboBox<>(new String[] {"equal", "not equal", "lower", "greater", "lower equal", "greater equal"});
        this.operationBox.setSelectedItem("equal");
        this.addUIElement("Lineseperator", this.operationBox);
    }

}
