package de.usd.cstchef.view.ui;



import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.util.ArrayList;

public class PlaceholderTextField extends JTextField implements FocusListener, DocumentListener {

    private boolean isPlaceholderSet;
    private boolean settingPlaceholder;
    private String placeholder;
    private ArrayList<TextChangedListener> listeners = new ArrayList<TextChangedListener>();

    public PlaceholderTextField(){
        super();
    }

    public PlaceholderTextField(String placeholder){
        this();
        this.setPlaceholder(placeholder);
        this.isPlaceholderSet = true;
        this.settingPlaceholder = false;
        this.renderPlaceholder(false);
        this.addFocusListener(this);
        this.getDocument().addDocumentListener(this);
    }

    public void addTextChangedListener(TextChangedListener listener){
        this.listeners.add(listener);
    }

    public void removeTextChangedListener(TextChangedListener listener){
        this.listeners.remove(listener);
    }

    public String getPlaceholder() {
        return placeholder;
    }

    public void setPlaceholder(final String s) {
        placeholder = s;
    }

    @Override
    public void focusGained(FocusEvent e) {
        if(isPlaceholderSet){
            this.renderPlaceholder(true);
            this.isPlaceholderSet = false;
        }
    }

    @Override
    public void focusLost(FocusEvent e) {
        if(this.getText() == null || this.getText().isEmpty()){
            this.isPlaceholderSet = true;
            this.renderPlaceholder(false);
        }
    }

    public void renderPlaceholder(boolean emptyPlaceholder){
        this.settingPlaceholder = true;
        if(!emptyPlaceholder){
            this.setText(this.getPlaceholder());
        }
        else{
            this.setText("");
        }        
        this.settingPlaceholder = false;
    }

    @Override
    public void changedUpdate(DocumentEvent arg0) {
        if(!this.settingPlaceholder){
            for (TextChangedListener listener : this.listeners) {
                listener.textChanged();
            }
        }
    }

    @Override
    public void insertUpdate(DocumentEvent arg0) {
        if(!this.settingPlaceholder){
            for (TextChangedListener listener : this.listeners) {
                listener.textChanged();
            }
        }
    }

    @Override
    public void removeUpdate(DocumentEvent arg0) {
        if(!this.settingPlaceholder){
            for (TextChangedListener listener : this.listeners) {
                listener.textChanged();
            }
        }
    }
}