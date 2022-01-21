package de.usd.cstchef.operations.arithmetic;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "List - Multiply", category = OperationCategory.ARITHMETIC, description = "Multiplies a list of numbers.")
public class MultiplyList extends ArithmeticDelimiterOperation
{
    @Override
    protected double calculate(double a, double b)
    {
        return a * b;
    }
}