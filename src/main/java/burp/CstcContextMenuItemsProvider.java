package burp;

import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.view.View;
import de.usd.cstchef.view.filter.FilterState.BurpOperation;

public class CstcContextMenuItemsProvider implements ContextMenuItemsProvider {
    private MontoyaApi api;
    private View view;

    private Timer timer = new Timer();

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
                        highlightExtensionName();
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
                        highlightExtensionName();
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
                        highlightExtensionName();
                    }
                    
                });

                JMenuItem formattingResponseItem = new JMenuItem(view.getRecipePanelAtIndex(i).getRecipeName());
                incomingMenu.add(formattingResponseItem);
                incomingMenu.getItem(incomingMenu.getItemCount() - 1).addActionListener(new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        view.getRecipePanelAtIndex(index).setFormatMessage(event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(1), MessageType.RESPONSE);
                        highlightExtensionName();
                    }
                    
                });
            }
        }
        
        menuItems.add(outgoingMenu);
        menuItems.add(incomingMenu);

        return menuItems;
    }

    private void highlightExtensionName() {
        TimerTask task = new TimerTask() {

        @Override
        public void run() {
            SwingUtilities.invokeLater(new Runnable() {
                public void run(){
                    resetHighlighting();
                }
            });
        }
        
        };
        JTabbedPane parentTabbedPane = (JTabbedPane) BurpUtils.getInstance().getView().getParent();
        for(int i = 0; i < parentTabbedPane.getTabCount(); i++) {
            if(parentTabbedPane.getTitleAt(i).contains("CSTC")) {
                parentTabbedPane.setForegroundAt(i, new Color(0xff6633));
                timer.schedule(task, 3000);
                return;
            }
        }     
    }

    private void resetHighlighting() {
        JTabbedPane parentTabbedPane = (JTabbedPane) BurpUtils.getInstance().getView().getParent();
        for(int i = 0; i < parentTabbedPane.getTabCount(); i++) {
            if(parentTabbedPane.getTitleAt(i).contains("CSTC")) {
                parentTabbedPane.setForegroundAt(i, new Color(0x000000));
                return;
            }
        }
    }
}
