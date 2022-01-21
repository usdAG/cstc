package de.usd.cstchef.operations.arithmetic;

import javax.swing.JCheckBox;

import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Single - Divide", category = OperationCategory.ARITHMETIC, description = "Divide input by the given number")
public class Divide extends ArithmeticOperation {

    private JCheckBox reverse;

    @Override
    protected double calculate(double input_number, double static_number) {

        if( reverse.isSelected() ) {

            if( input_number == 0 )
                input_number = 1;

            return static_number / input_number;

        } else {

            if( static_number == 0 )
                static_number = 1;

            return input_number / static_number;

        }
    }

    @Override
    public void createUI() {
        super.createUI();

        this.reverse = new JCheckBox();
        this.addUIElement("Reverse", this.reverse);
    }
}
