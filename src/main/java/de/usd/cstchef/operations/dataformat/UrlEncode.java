package de.usd.cstchef.operations.dataformat;

import java.io.ByteArrayOutputStream;

import javax.swing.JCheckBox;

import org.bouncycastle.util.encoders.Hex;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Url Encode", category = OperationCategory.DATAFORMAT, description = "Url encode")
public class UrlEncode extends Operation {

	private JCheckBox checkbox;
	
	@Override
	protected byte[] perform(byte[] input) throws Exception {
		IBurpExtenderCallbacks cbs = BurpUtils.getInstance().getCallbacks();
		IExtensionHelpers helpers = cbs.getHelpers();
		
		byte[] result = null;
		if( checkbox.isSelected() ) {

			byte[] delimiter = "%".getBytes();
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			out.write(delimiter);
			
			for (int i = 0; i < input.length - 1; i++) {
				out.write(Hex.encode(new byte[] { input[i] }));
				out.write(delimiter);
			}
			
			out.write(Hex.encode(new byte[] { input[input.length - 1] }));
			result = out.toByteArray();
			
		} else {
			result = helpers.urlEncode(input);
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
