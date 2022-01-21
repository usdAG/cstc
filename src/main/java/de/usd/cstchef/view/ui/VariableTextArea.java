package de.usd.cstchef.view.ui;

import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.event.DocumentListener;

import de.usd.cstchef.Utils;
import de.usd.cstchef.view.PopupVariableMenu;


public class VariableTextArea extends JScrollPane {

    private JTextArea txtArea;

    public VariableTextArea() {
        this.txtArea = new JTextArea();
        this.setViewportView(this.txtArea);
        this.txtArea.setRows(5);
        this.txtArea.setComponentPopupMenu(new PopupVariableMenu(this.txtArea));
    }

    public String getText() {
        String text = this.txtArea.getText();
        return Utils.replaceVariables(text);
    }

    public byte[] getBytes() {
        byte[] bytes = this.txtArea.getText().getBytes();
        return Utils.replaceVariablesByte(bytes);
    }

    public void setText(String text) {
        this.txtArea.setText(text);
    }

    public String getRawText() {
        return this.txtArea.getText();
    }

    public void addDocumentListener(DocumentListener notifyChangeListener) {
        this.txtArea.getDocument().addDocumentListener(notifyChangeListener);
    }

}
