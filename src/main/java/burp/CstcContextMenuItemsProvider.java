package burp;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import de.usd.cstchef.Utils.MessageType;
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
        JMenuItem incomingHttpResponseMenu = new JMenuItem("Send to Incoming HTTP Responses");
        JMenuItem incomingProxyRequestMenu = new JMenuItem("Send to Incoming Proxy Requests");
        JMenuItem outgoingHttpRequestMenu = new JMenuItem("Send to Outgoing HTTP Requests");
        JMenuItem outgoingProxyResponseMenu = new JMenuItem("Send to Outgoing Proxy Responses");
        JMenuItem incomingReqFormatMenu = new JMenuItem("Send request to Formatting");
        JMenuItem incomingResFormatMenu = new JMenuItem("Send response to Formatting");
        
        menuItems.add(outgoingHttpRequestMenu);
        menuItems.add(outgoingProxyResponseMenu);
        menuItems.add(incomingHttpResponseMenu);
        menuItems.add(incomingProxyRequestMenu);
        menuItems.add(incomingReqFormatMenu);
        menuItems.add(incomingResFormatMenu);

        incomingHttpResponseMenu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                view.getIncomingHttpResponseRecipePanel().setInput(event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0));
            }
        });
        
        incomingProxyRequestMenu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                view.getIncomingProxyRequestRecipePanel().setInput(event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0));
            }
        });

        outgoingHttpRequestMenu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                view.getOutgoingHttpRequestRecipePanel().setInput(event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0));
            }
        });
        
        outgoingProxyResponseMenu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                view.getOutgoingProxyResponseRecipePanel().setInput(event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0));
            }
        });

        incomingResFormatMenu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                view.getFormatRecipePanel().setFormatMessage(event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0), MessageType.RESPONSE);
            }
        });

        incomingReqFormatMenu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                view.getFormatRecipePanel().setFormatMessage(event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0), MessageType.REQUEST);
            }
        });

        return menuItems;
    }
}
