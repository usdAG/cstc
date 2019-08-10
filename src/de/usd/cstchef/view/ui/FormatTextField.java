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
		this.formatBox = new JComboBox<>(new String[] {"UTF-8", "Hex", "Latin1", "Base64"});
		this.formatBox.addActionListener(this);

		Box box = Box.createHorizontalBox();
		box.add(formatBox);
		box.add(Box.createHorizontalStrut(10));
		box.add(txtField);

		this.add(box);
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
		String text = this.txtField.getText();
		byte[] result = null;

		switch ((String) this.formatBox.getSelectedItem()) {
		case "Hex":
			result = Hex.decode(text);
			break;
		case "Base64":
			result = Base64.getDecoder().decode(text);
			break;
		case "Latin1":
			result = text.getBytes("ISO-8859-1");
			break;
		case "UTF-8":
			result = text.getBytes("UTF-8");
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
	}

}
