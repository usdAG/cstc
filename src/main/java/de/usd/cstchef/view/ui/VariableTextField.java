package de.usd.cstchef.view.ui;

import javax.swing.JTextField;

import burp.api.montoya.core.ByteArray;
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

    public ByteArray getBytes() {
        ByteArray bytes = ByteArray.byteArray(super.getText());
        return Utils.replaceVariablesByte(bytes);
    }

    public String getRawText() {
        return super.getText();
    }

}
