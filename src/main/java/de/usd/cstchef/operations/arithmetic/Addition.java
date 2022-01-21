package de.usd.cstchef.operations.arithmetic;

import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Single - Add", category = OperationCategory.ARITHMETIC, description = "Add to the input the given number.")
public class Addition extends ArithmeticOperation {

    @Override
    protected double calculate(double input_number, double static_number) {
        return input_number + static_number;
    }
}
