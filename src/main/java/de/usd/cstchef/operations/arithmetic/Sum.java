package de.usd.cstchef.operations.arithmetic;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "List - Sum", category = OperationCategory.ARITHMETIC, description = "Sums a list of numbers.")
public class Sum extends ArithmeticDelimiterOperation
{

    @Override
    protected double calculate(double a, double b)
    {
        return a + b;
    }
}