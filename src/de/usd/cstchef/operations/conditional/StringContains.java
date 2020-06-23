package de.usd.cstchef.operations.conditional;

import javax.swing.JCheckBox;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "String Contains", category = OperationCategory.CONDITIONAL, description = "Skip if input contains")
public class StringContains extends Conditionaloperation {

	private JCheckBox invert;
	private JCheckBox caseSensitive;
	
	@Override
	protected byte[] perform(byte[] input) throws Exception {
		
		IBurpExtenderCallbacks cbs = BurpUtils.getInstance().getCallbacks();
		IExtensionHelpers helpers = cbs.getHelpers();
		int start = helpers.indexOf(input, this.expr.getBytes(), caseSensitive.isSelected(), 0, input.length);
		
		if( (start >= 0) ^ invert.isSelected() ) {
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
		
		this.caseSensitive = new JCheckBox();
		this.addUIElement("Case Sensitive", this.caseSensitive);
	}
	
}
