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
import de.usd.cstchef.view.filter.FilterState.BurpOperation;

public class CstcContextMenuItemsProvider implements ContextMenuItemsProvider {
    private MontoyaApi api;
    private View view;

    public CstcContextMenuItemsProvider(MontoyaApi api, View view)
    {
        this.api = api;
        this.view = view;

    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {

        List<Component> menuItems = new ArrayList<>();
        JMenu outgoingMenu = new JMenu("Send request to");
        JMenu incomingMenu = new JMenu("Send response to");

        for(int i = 0; i < view.getNumOfRecipePanels(); i++) {
            final int index = i;
            if(view.getRecipePanelAtIndex(i).getOperation().equals(BurpOperation.OUTGOING)) {
                JMenuItem outgoingItem = new JMenuItem(view.getRecipePanelAtIndex(i).getRecipeName());
                outgoingMenu.add(outgoingItem);
                outgoingMenu.getItem(outgoingMenu.getItemCount() - 1).addActionListener(new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        view.getRecipePanelAtIndex(index).setFormatMessage(event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0), MessageType.REQUEST);
                    }
                    
                });
            }
            else if(view.getRecipePanelAtIndex(i).getOperation().equals(BurpOperation.INCOMING)) {
                JMenuItem incomingItem = new JMenuItem(view.getRecipePanelAtIndex(i).getRecipeName());
                incomingMenu.add(incomingItem);
                incomingMenu.getItem(incomingMenu.getItemCount() - 1).addActionListener(new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        view.getRecipePanelAtIndex(index).setFormatMessage(event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(1), MessageType.RESPONSE);
                    }
                    
                });
            }
            else {
                JMenuItem formattingRequestItem = new JMenuItem(view.getRecipePanelAtIndex(i).getRecipeName());
                outgoingMenu.add(formattingRequestItem);
                outgoingMenu.getItem(outgoingMenu.getItemCount() - 1).addActionListener(new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        view.getRecipePanelAtIndex(index).setFormatMessage(event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0), MessageType.REQUEST);
                    }
                    
                });

                JMenuItem formattingResponseItem = new JMenuItem(view.getRecipePanelAtIndex(i).getRecipeName());
                incomingMenu.add(formattingResponseItem);
                incomingMenu.getItem(incomingMenu.getItemCount() - 1).addActionListener(new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        view.getRecipePanelAtIndex(index).setFormatMessage(event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(1), MessageType.RESPONSE);
                    }
                    
                });
            }
        }
        
        menuItems.add(outgoingMenu);
        menuItems.add(incomingMenu);

        return menuItems;
    }
}
