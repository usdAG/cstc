package de.usd.cstchef.operations.setter;

import java.util.Arrays;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import de.usd.cstchef.Utils;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Line Setter", category = OperationCategory.SETTER, description = "Sets a line to the specified value.")
public class LineSetter extends SetterOperation {

	private JCheckBox append;
	private JComboBox<String> formatBox;

	@Override
	protected byte[] perform(byte[] input) throws Exception {

		int lineNumber;
		try {
			String number = getWhere();
			lineNumber = Integer.valueOf(number);
		} catch( Exception e ) {
			return input;
		}

		if( lineNumber <= 0 )
			return input;

		byte[] newValue = getWhatBytes();
		byte[] lineEndings = "\r\n".getBytes();
		switch ((String) this.formatBox.getSelectedItem()) {
		case "\\r\\n":
			lineEndings = "\r\n".getBytes();
			break;
		case "\\r":
			lineEndings = "\r".getBytes();
			break;
		case "\\n":
			lineEndings = "\n".getBytes();
			break;
		}

		IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
		IExtensionHelpers helpers = callbacks.getHelpers();
		int length = input.length;

		int start = 0;
		int offset = 0;
		int counter = 0;
		while( counter < lineNumber - 1 ) {
			offset = helpers.indexOf(input, lineEndings, false, start, length);
			if( offset >= 0 ) {
				start = offset + lineEndings.length;
				counter++;
			} else {
				break;
			}
		}

		int end = helpers.indexOf(input, lineEndings, false, start, length);
		if( end < 0 )
			end = length;

		if( append.isSelected() ) {
			byte[] value = new byte[newValue.length + lineEndings.length];
			System.arraycopy(lineEndings, 0, value, 0, lineEndings.length);
			System.arraycopy(newValue, 0, value, lineEndings.length, newValue.length);
			return Utils.insertAtOffset(input, end, end, value);
		} else {
			return Utils.insertAtOffset(input, start, end, newValue);
		}
	}

	@Override
	public void createUI() {
		super.createUI();
		this.append = new JCheckBox("Insert below");
	    this.append.setSelected(false);
		this.addUIElement(null, this.append, "checkbox1");

		this.formatBox = new JComboBox<>(new String[] {"\\r\\n", "\\r", "\\n"});
		this.formatBox.setSelectedItem("\\r\\n");
		this.addUIElement("Lineseperator", this.formatBox);
	}

}
