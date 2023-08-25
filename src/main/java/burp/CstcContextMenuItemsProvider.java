package burp;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import de.usd.cstchef.view.View;

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
        JMenuItem incomingMenu = new JMenuItem("Send to CSTC (Incoming)");
        JMenuItem outgoingMenu = new JMenuItem("Send to CSTC (Outgoing)");
        JMenuItem incomingFormatMenu = new JMenuItem("Send to CSTC (Formating)");

        menuItems.add(incomingMenu);
        menuItems.add(outgoingMenu);
        menuItems.add(incomingFormatMenu);

        incomingMenu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                List<HttpRequestResponse> msgs = event.selectedRequestResponses();
                if (msgs != null && msgs.size() > 0) {
                    view.getIncomingRecipePanel().setInput(msgs.get(0));
                }
            }
        });

        outgoingMenu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                List<HttpRequestResponse> msgs = event.selectedRequestResponses();
                if (msgs != null && msgs.size() > 0) {
                    view.getOutgoingRecipePanel().setInput(msgs.get(0));
                }

            }
        });

        incomingFormatMenu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                List<HttpRequestResponse> msgs = event.selectedRequestResponses();
                if (msgs != null && msgs.size() > 0) {
                    view.getFormatRecipePanel().setInput(msgs.get(0));
                }
            }
        });

        return menuItems;
    }
}
