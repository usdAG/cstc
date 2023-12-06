package de.usd.cstchef.view;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.HashMap;
import java.util.SortedMap;
import java.util.TreeMap;

import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.text.JTextComponent;

import burp.api.montoya.core.ByteArray;

public class PopupVariableMenu extends JPopupMenu implements ActionListener, PopupMenuListener {

    private JTextComponent parent;
    private static SortedMap<String, ByteArray> variableMap;

    public PopupVariableMenu(JTextComponent parent) {
        super();
        this.parent = parent;
        this.addPopupMenuListener(this);

    }

    public void refreshMenu() {
        this.removeAll();

        for (String key : variableMap.keySet()) {
            JMenuItem item = new JMenuItem(key);
            item.addActionListener(this);
            this.add(item);
        }
    }

    public static void refresh(HashMap<String, ByteArray> variables) {
        if (variables == null) {
            variableMap = new TreeMap<String,ByteArray>();
        } else {
            variableMap = new TreeMap<String, ByteArray>(variables);
        }
    }

    @Override
    public void actionPerformed(ActionEvent arg0) {
        parent.setText(parent.getText() + "$" + arg0.getActionCommand());
    }

    @Override
    public void popupMenuCanceled(PopupMenuEvent arg0) {
        // not needed
    }

    @Override
    public void popupMenuWillBecomeInvisible(PopupMenuEvent arg0) {
        // not needed
    }

    @Override
    public void popupMenuWillBecomeVisible(PopupMenuEvent arg0) {
        this.refreshMenu();
    }

}
