package de.usd.cstchef.operations.arithmetic;

import java.util.Set;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;

import de.usd.cstchef.Utils;
import de.usd.cstchef.operations.Operation;

public abstract class ArithmeticDelimiterOperation extends Operation {

    private JComboBox<String> delimiterBox;
    private JCheckBox floatCheckBox;

    @Override
    protected byte[] perform(byte[] input) throws Exception {
        String delimiterKey = (String) this.delimiterBox.getSelectedItem();
        String delimiter = Utils.delimiters.get(delimiterKey);
        String[] lines = new String(input).split(delimiter);
        if (lines.length < 2) {
            return input;
        }

        double[] numbers = new double[lines.length];

        double result = Utils.parseNumber(lines[0].trim());
        numbers[0] = result;
        double val;
        for (int i = 1; i < lines.length; i++) {
            val = Utils.parseNumber(lines[i].trim());
            numbers[i] = val;
            result = this.calculate(result, val);
        }

        result = onFinish(result, numbers);
        String str = "";
        if (floatCheckBox.isSelected()) {
            str = String.valueOf(result);
        }
        else {
            str = String.valueOf(Math.round(result));
        }
        return str.getBytes();
    }

    protected double onFinish(double result, double[] lines) {
        return result;
    }

    protected abstract double calculate(double a, double b);

    @Override
    public void createUI() {
        Set<String> delimSet = Utils.delimiters.keySet();
        String[] delimiters = delimSet.toArray(new String[delimSet.size()]);

        this.delimiterBox = new JComboBox<String>(delimiters);
        this.addUIElement("Delimiter", this.delimiterBox);

        this.floatCheckBox = new JCheckBox();
        this.addUIElement("Point Number", this.floatCheckBox);
    }

}
