package burp;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenu;
import javax.swing.JMenuItem;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.view.View;

public class CstcContextMenuItemsProvider implements ContextMenuItemsProvider {
    private MontoyaApi api;
    private View view;
    private static List<Component> menuItems = new ArrayList<>();
    private static JMenu outgoingMenu = new JMenu("Send request to");
    private JMenu incomingMenu = new JMenu("Send response to");

    public CstcContextMenuItemsProvider(MontoyaApi api, View view)
    {
        this.api = api;
        this.view = view;

        JMenuItem outgoingItem = new JMenuItem(View.recipePanelNames[0]);
        outgoingMenu.add(outgoingItem);

        JMenuItem incomingItem = new JMenuItem(View.recipePanelNames[1]);
        incomingMenu.add(incomingItem);

        JMenuItem requestToFormattingItem = new JMenuItem("Send request to Formatting");
        JMenuItem responseToFormattingItem = new JMenuItem("Send response to Formatting");
        
        menuItems.add(outgoingMenu);
        menuItems.add(incomingMenu);
        menuItems.add(requestToFormattingItem);
        menuItems.add(responseToFormattingItem);
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {

        //TODO
        /*
        for(int i = 0; i < incomingMenu.getItemCount(); i++) {
            incomingMenu.getItem(i).addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    for(int j = 0; j < View.getNumOfRecipePanels(); j++) {
                        if(View.getRecipePanelAtIndex(j).getRecipeName().equals(outgoingMenu.getItem(j).getText())) {
                            View.getRecipePanelAtIndex(j).setInput(event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0));
                        }
                    }
                }
            });
        }
        */

        ((JMenuItem) menuItems.get(2)).addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                View.getRecipePanelAtIndex(2).setFormatMessage(event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0), MessageType.REQUEST);
            }
        });

        ((JMenuItem) menuItems.get(3)).addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                View.getRecipePanelAtIndex(2).setFormatMessage(event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0), MessageType.RESPONSE);
            }
        });

        return menuItems;
    }

    public static void addMenuItem(JMenuItem item, boolean isOutgoing) {
        int i = isOutgoing ? 0 : 1;
        ((JMenu) CstcContextMenuItemsProvider.menuItems.get(i)).add(item);
    }
}
