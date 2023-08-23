package de.usd.cstchef.view.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.swing.Box;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.event.DocumentListener;
import org.bouncycastle.util.encoders.Hex;

public class FormatTextField extends JPanel implements ActionListener {

    public VariableTextField txtField;
    private JComboBox<String> formatBox;
    private DocumentListener docListener;

    public FormatTextField() {
        this.setLayout(new BorderLayout());
        this.setBackground(new Color(0, 0, 0, 0));
        this.txtField = new VariableTextField();
        this.formatBox = new JComboBox<>(new String[] { "Raw", "UTF-8", "Hex", "Latin1", "Base64" });
        this.formatBox.addActionListener(this);

        Box box = Box.createHorizontalBox();
        box.add(formatBox);
        box.add(Box.createHorizontalStrut(10));
        box.add(txtField);

        this.add(box);
    }

    public void addOption(String option) {
        this.formatBox.addItem(option);
    }

    public void setDefault(String option) {
        for (int i = 0; i < this.formatBox.getItemCount(); i++) {
            if (this.formatBox.getItemAt(i).equals(option)) {
                this.formatBox.setSelectedItem(this.formatBox.getItemAt(i));
            }
        }
    }

    public Map<String, String> getValues() {
        Map<String, String> values = new HashMap<>();
        values.put("text", this.txtField.getText());
        values.put("encoding", this.formatBox.getSelectedItem().toString());
        return values;
    }

    public void setValues(Map<String, String> values) {
        String text = values.get("text");
        this.txtField.setText(text);
        Object encoding = values.get("encoding");
        this.formatBox.setSelectedItem(encoding);
    }

    public byte[] getText() throws UnsupportedEncodingException {

        byte[] raw = this.txtField.getBytes();
        byte[] result = null;

        switch ((String) this.formatBox.getSelectedItem()) {
            case "Raw":
                result = raw;
                break;
            case "Hex":
                result = Hex.decode(raw);
                break;
            case "Base64":
                result = Base64.getDecoder().decode(raw);
                break;
            case "Latin1":
                result = this.txtField.getText().getBytes("ISO-8859-1");
                break;
            case "UTF-8":
                result = this.txtField.getText().getBytes("UTF-8");
                break;
            case "Empty":
                result = new byte[16];
                break;
        }
        return result;
    }

    public void addDocumentListener(DocumentListener listener) {
        this.docListener = listener;
        this.txtField.getDocument().addDocumentListener(listener);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (this.docListener != null) {
            this.docListener.changedUpdate(null);
        }
        if (this.formatBox.getSelectedItem().equals("Empty")) {
            this.txtField.setEnabled(false);
            this.txtField.setDisabledTextColor(Color.GRAY);
        } else {
            this.txtField.setEnabled(true);
        }
    }

}
