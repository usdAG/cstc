package de.usd.cstchef.operations.dataformat;

import java.io.ByteArrayOutputStream;

import javax.swing.JCheckBox;

import org.apache.commons.text.StringEscapeUtils;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTML Encode", category = OperationCategory.DATAFORMAT, description = "HTML Encode")
public class HtmlEncode extends Operation {

	private JCheckBox checkbox;

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		
		byte[] result = null;
		if( checkbox.isSelected() ) {

			byte[] delimiter = "&#".getBytes();
			byte[] closer = ";".getBytes();
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			
			out.write(delimiter);
			for (int i = 0; i < input.length - 1; i++) {
				out.write(String.valueOf(Byte.toUnsignedInt(input[i])).getBytes());
				out.write(closer);
				out.write(delimiter);
			}
			
			out.write(String.valueOf(Byte.toUnsignedInt(input[input.length - 1])).getBytes());
			out.write(closer);
			result = out.toByteArray();
			
		} else {
			String tmp = new String(input);
			tmp = StringEscapeUtils.escapeHtml4(tmp);
			result = tmp.getBytes();
		}
		
		return result;
	}

	@Override
	public void createUI() {
		this.checkbox = new JCheckBox("Encode all");
	    this.checkbox.setSelected(false);
		this.addUIElement(null, this.checkbox, "checkbox1");
	}
}
