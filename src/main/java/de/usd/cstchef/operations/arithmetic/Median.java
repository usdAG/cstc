package de.usd.cstchef.operations.arithmetic;

import java.util.Arrays;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "List - Median", category = OperationCategory.ARITHMETIC, description = "Computes the median of a list of numbers.")
public class Median extends ArithmeticDelimiterOperation
{
    @Override
    protected double calculate(double a, double b)
    {
        return a;
    }

    @Override
    protected double onFinish(double intermediateResult, double[] lines)
    {
        Arrays.sort(lines);
        double result;

        if (lines.length % 2 == 0)
        {
            int mid = lines.length / 2;
            result = (lines[mid] + lines[mid - 1]) / 2;
        }

        else
        {
            result = lines[(int) (Math.floor(lines.length / 2))];
        }

        return result;
    }
}