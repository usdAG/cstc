package de.usd.cstchef.view;

import java.awt.Component;

import burp.BurpUtils;
import burp.IMessageEditorTab;
import burp.ITextEditor;
import burp.Logger;

public class FormatTab implements IMessageEditorTab {
	private ITextEditor txtInput;
	private boolean editable;
	private RecipePanel responseFormatRecipePanel;
	private RecipePanel requestFormatRecipePanel;
	private byte[] currentMessage;

	public FormatTab(RecipePanel requestFormatRecipePanel, RecipePanel responseFormatRecipePanel, boolean editable) {
		this.editable = editable;
		this.responseFormatRecipePanel = responseFormatRecipePanel;
		this.requestFormatRecipePanel = requestFormatRecipePanel;
		txtInput = BurpUtils.getInstance().getCallbacks().createTextEditor();
		txtInput.setEditable(editable);
	}

	@Override
	public String getTabCaption() {
		return "CSTC";
	}

	@Override
	public Component getUiComponent() {
        return txtInput.getComponent();
	}

	@Override
	public boolean isEnabled(byte[] content, boolean isRequest) {
		return true;
	}

	@Override
	public void setMessage(byte[] content, boolean isRequest) {
		currentMessage = content;
		
		if (content == null) {
            txtInput.setText("Nothing here".getBytes());
            txtInput.setEditable(false);
            return;
        }
		RecipePanel recipe = isRequest ? this.requestFormatRecipePanel : this.responseFormatRecipePanel;
		Logger.getInstance().log("baking new stuff");
		byte[] result = recipe.bake(content);
		this.txtInput.setText(result);
	}

	@Override
	public byte[] getMessage() {
		return currentMessage;
	}

	@Override
	public boolean isModified() {
        return txtInput.isTextModified();
	}

	@Override
	public byte[] getSelectedData() {
        return txtInput.getSelectedText();
	}

}