package de.usd.cstchef.operations.conditional;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JCheckBox;

import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Regex Match", category = OperationCategory.CONDITIONAL, description = "Skip if regex matches")
public class RegexMatch extends ConditionalOperation {

	private JCheckBox invert;

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		
		Pattern p = Pattern.compile(this.expr.getText());
		Matcher m = p.matcher(new String(input));

		if( m.matches() ^ invert.isSelected() ) {
			this.setOperationSkip();
			this.setLaneSkip();
		} else {
			this.resetSkips();
		}
		
		return input;
	}
	
	@Override
	public void createUI() {
		super.createUI();
		
		this.invert = new JCheckBox();
		this.addUIElement("Invert Match", this.invert);
	}
	
}
