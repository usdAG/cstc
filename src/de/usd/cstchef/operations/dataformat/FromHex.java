package de.usd.cstchef.operations.dataformat;

import java.util.Set;

import javax.swing.JComboBox;
import org.bouncycastle.util.encoders.Hex;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.dataformat.ToHex.Delimiter;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "From Hex", category = OperationCategory.DATAFORMAT, description = "From hex")
public class FromHex extends Operation {

	private JComboBox<String> delimiterBox;

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		String selectedKey = (String) this.delimiterBox.getSelectedItem();
		Delimiter delimiter = ToHex.delimiters.get(selectedKey);

		if (delimiter.value.length == 0) { // No delimiter
			return Hex.decode(input);
		}
		
		String delimiterStr = new String(delimiter.value);		
		String inputStr = new String(input);
		inputStr = inputStr.replace(delimiterStr, "");
		
		return Hex.decode(inputStr);
	}

	@Override
	public void createUI() {
		Set<String> choices = ToHex.delimiters.keySet();
		delimiterBox = new JComboBox<String>(choices.toArray(new String[choices.size()]));
		delimiterBox.setSelectedIndex(0);
		
		this.addUIElement("Delimiter", delimiterBox);
	}

}
