package de.usd.cstchef.view;

import java.awt.Component;
import java.util.Arrays;

import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import burp.BurpUtils;
import burp.IMessageEditor;

public class BurpEditorWrapper implements IMessageEditor, DocumentListener {

	private JTextArea fallbackArea;
	private IMessageEditor burpEditor;
	public boolean fallbackMode;
	boolean isModified;
	byte[] lastContent;

	public BurpEditorWrapper(IMessageEditorController controller, boolean editable) {
		if (BurpUtils.inBurp()) {
			this.burpEditor = BurpUtils.getInstance().getCallbacks().createMessageEditor(controller, editable);
			fallbackMode = false;
		} else {
			this.fallbackArea = new JTextArea();
			this.fallbackArea.getDocument().addDocumentListener(this);
			fallbackMode = true;
		}
	}

	@Override
	public Component getComponent() {
		if (fallbackMode) {
			JScrollPane inputScrollPane = new JScrollPane(fallbackArea);
			return inputScrollPane;
		}
		return burpEditor.getComponent();
	}

	@Override
	public byte[] getMessage() {
		byte[] result;
		result = fallbackMode ? fallbackArea.getText().getBytes() : burpEditor.getMessage();
		return result == null ? new byte[0] : result;
	}

	@Override
	public byte[] getSelectedData() {
		return null;
	}

	@Override
	public int[] getSelectionBounds() {
		return null;
	}

	@Override
	public boolean isMessageModified() {
		if (fallbackMode) {
			boolean state = this.isModified;
			this.isModified = false;
			return state;
		}
		// TODO: a little hack here
		if (!Arrays.equals(lastContent, getMessage())) {
			lastContent = getMessage();
			return true;
		}
		return false;
	}

	@Override
	public void setMessage(byte[] arg0, boolean arg1) {
		if (fallbackMode) {
			fallbackArea.setText(new String(arg0));
		} else {
			this.lastContent = arg0;
			burpEditor.setMessage(arg0, arg1); //TODO fix second parameter
		}
	}

	@Override
	public void changedUpdate(DocumentEvent e) {
		this.isModified = true;
	}

	@Override
	public void insertUpdate(DocumentEvent e) {
		this.isModified = true;
	}

	@Override
	public void removeUpdate(DocumentEvent e) {
		this.isModified = true;
	}

}
