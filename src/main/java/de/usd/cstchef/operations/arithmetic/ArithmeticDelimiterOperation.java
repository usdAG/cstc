package de.usd.cstchef.operations.arithmetic;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;

import de.usd.cstchef.Delimiter;
import de.usd.cstchef.Utils;
import de.usd.cstchef.operations.Operation;

public abstract class ArithmeticDelimiterOperation extends Operation
{
    private JComboBox<String> delimiterBox;
    private JCheckBox floatCheckBox;

    protected Delimiter getDelimiter() throws IllegalArgumentException
    {
        String delimString = (String)this.delimiterBox.getSelectedItem();
        Delimiter delim = Delimiter.getByName(delimString);

        if( delim == null )
            throw new IllegalArgumentException("Invalid delimiter.");

        return delim;
    }

    protected boolean isFloat()
    {
        return floatCheckBox.isSelected();
    }

    @Override
    protected byte[] perform(byte[] input) throws Exception
    {
        String delimiter = getDelimiter().getValue();
        String[] lines = new String(input).split(delimiter);

        if (lines.length < 2)
            return input;

        double[] numbers = new double[lines.length];
        double result = Utils.parseNumber(lines[0].trim());

        for(int i = 1; i < lines.length; i++)
        {
            numbers[i] = Utils.parseNumber(lines[i].trim());
            result = this.calculate(result, numbers[i]);
        }

        result = onFinish(result, numbers);

        if( !isFloat() )
            return String.valueOf(Math.round(result)).getBytes();

        return String.valueOf(result).getBytes();
    }

    protected double onFinish(double result, double[] lines)
    {
        return result;
    }

    protected abstract double calculate(double a, double b);

    @Override
    public void createUI()
    {
        this.delimiterBox = new JComboBox<String>(Delimiter.getNames());
        this.addUIElement("Delimiter", this.delimiterBox);

        this.floatCheckBox = new JCheckBox();
        this.addUIElement("Point Number", this.floatCheckBox);
    }

}
