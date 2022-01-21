package de.usd.cstchef.operations.setter;

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;

import javax.swing.JCheckBox;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;

import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "JSON", category = OperationCategory.SETTER, description = "Set value of json object.")
public class JsonSetter extends SetterOperation implements ActionListener {

	private JCheckBox addIfNotPresent;
	private VariableTextField path;
	
	@Override
	protected byte[] perform(byte[] input) throws Exception {
		
		if( getWhere().equals("") )
			return input; 
		
		DocumentContext document = JsonPath.parse(new String(input));
		
		try {
			document.read(getWhere());
		} catch( Exception e ) {
			
			if( !addIfNotPresent.isSelected() )
				throw new IllegalArgumentException("Key not found.");
			
			String insertPath = this.path.getText();
			if( insertPath.equals("Insert-Path") || insertPath.equals("") )
				insertPath = "$";
				
			document = document.put(insertPath, getWhere(), getWhat());
			return document.jsonString().getBytes();
		}
		
		document.set(getWhere(), getWhat());
		return document.jsonString().getBytes();
	}
	
	@Override
	public void createUI() {
		super.createUI();
		this.addIfNotPresent = new JCheckBox("Add if not present");
	    this.addIfNotPresent.setSelected(true);
	    this.addIfNotPresent.addActionListener(this);
		this.addUIElement(null, this.addIfNotPresent, "checkbox1");
		
		this.path = new VariableTextField();
		this.path.setText("Insert-Path");
    	this.path.setForeground(Color.GRAY);
		this.path.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
			    if (path.getText().equals("Insertion Path")) {
			    	path.setText("");
			    	path.setForeground(null);
			    }
			}
			@Override
			public void focusLost(FocusEvent e) {
			    if (path.getText().isEmpty()) {
			    	path.setForeground(Color.GRAY);
                    path.setText("Insertion Path");
			    }
			}
		});
        this.addUIElement(null, this.path, "textbox1");
	}

	@Override
	public void actionPerformed(ActionEvent arg0) {
        if( arg0.getSource() == this.addIfNotPresent ) {
          if( this.addIfNotPresent.isSelected() ) {
        	  this.path.setEditable(true);
          } else {
        	  this.path.setEditable(false);
          }
        } 
	}
}
