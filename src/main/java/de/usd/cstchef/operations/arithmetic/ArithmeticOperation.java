package de.usd.cstchef.operations.arithmetic;

import javax.swing.JCheckBox;
import javax.swing.JTextField;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;

public abstract class ArithmeticOperation extends Operation
{
    private JTextField numberInput;
    private JCheckBox floatCheckBox;

    protected double getNumber()
    {
        return Double.valueOf(numberInput.getText());
    }

    protected boolean isFloat()
    {
        return floatCheckBox.isSelected();
    }

    @Override
    protected ByteArray perform(ByteArray input) throws Exception
    {
        try
        {
            String i = new String(input.getBytes());

            if (i.isEmpty())
                i = "0";

            Double input_number = Double.valueOf(i);
            Double static_number = getNumber();
            Double result_number = calculate(input_number, static_number);

            if ( isFloat() )
                return ByteArray.byteArray(String.valueOf(result_number));

            return ByteArray.byteArray(String.valueOf(Math.round(result_number)));

        }

        catch( Exception e )
        {
            throw new IllegalArgumentException("Input is not a number.");
        }
    }

    protected abstract double calculate(double input_number, double static_number);

    @Override
    public void createUI()
    {
        this.numberInput = new JTextField("1");
        this.addUIElement("Number", this.numberInput);

        this.floatCheckBox = new JCheckBox();
        this.addUIElement("Point Number", this.floatCheckBox);
    }
}