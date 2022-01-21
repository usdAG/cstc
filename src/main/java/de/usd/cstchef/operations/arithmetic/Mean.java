package de.usd.cstchef.operations.arithmetic;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "List - Mean", category = OperationCategory.ARITHMETIC, description = "Computes the mean of a list of numbers.")
public class Mean extends ArithmeticDelimiterOperation {

    @Override
    protected double calculate(double a, double b) {
        return a + b;
    }

    @Override
    protected double onFinish(double result, double[] lines) {
        return result / lines.length;
    }

}
