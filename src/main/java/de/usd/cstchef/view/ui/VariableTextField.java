package de.usd.cstchef.view.ui;

import javax.swing.JTextField;

import de.usd.cstchef.Utils;
import de.usd.cstchef.view.PopupVariableMenu;

public class VariableTextField extends JTextField {

    public VariableTextField() {
        super();
        this.setComponentPopupMenu(new PopupVariableMenu(this));
    }

    @Override
    public String getText() {
        String text = super.getText();
        return Utils.replaceVariables(text);
    }

    public byte[] getBytes() {
        byte[] bytes = super.getText().getBytes();
        return Utils.replaceVariablesByte(bytes);
    }

    public String getRawText() {
        return super.getText();
    }

}
