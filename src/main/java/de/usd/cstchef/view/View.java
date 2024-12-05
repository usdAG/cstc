package de.usd.cstchef.view;

import java.awt.BorderLayout;
import java.security.Security;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.WindowConstants;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import burp.BurpUtils;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.view.filter.FilterState;
import de.usd.cstchef.view.filter.FilterState.BurpOperation;

public class View extends JPanel {

    private RecipePanel incomingHttpResponseRecipePanel;
    private RecipePanel incomingProxyRequestRecipePanel;
    private RecipePanel outgoingHttpRequestRecipePanel;
    private RecipePanel outgoingProxyResponseRecipePanel;
    private RecipePanel formatRecipePanel;

    public View(){
        this(new FilterState());
    }

    public View(FilterState state) {
        Security.addProvider(new BouncyCastleProvider());

        this.setLayout(new BorderLayout());
        JTabbedPane tabbedPane = new JTabbedPane();

        incomingHttpResponseRecipePanel = new RecipePanel(BurpOperation.INCOMING_HTTP_RESPONSE, MessageType.RESPONSE);
        incomingProxyRequestRecipePanel = new RecipePanel(BurpOperation.INCOMING_PROXY_REQUEST, MessageType.REQUEST);
        outgoingHttpRequestRecipePanel = new RecipePanel(BurpOperation.OUTGOING_HTTP_REQUEST, MessageType.REQUEST);
        outgoingProxyResponseRecipePanel = new RecipePanel(BurpOperation.OUTGOING_PROXY_RESPONSE, MessageType.RESPONSE);
        formatRecipePanel = new RecipePanel(BurpOperation.FORMAT, MessageType.RAW);

        tabbedPane.addTab("Incoming Proxy Requests", null, incomingProxyRequestRecipePanel, "Incoming requests from the client application.");
        tabbedPane.addTab("Outgoing HTTP Requests", null, outgoingHttpRequestRecipePanel, "Outgoing requests from any tool of Burp.");
        tabbedPane.addTab("Incoming HTTP Responses", null, incomingHttpResponseRecipePanel, "Responses from the server.");
        tabbedPane.addTab("Outgoing Proxy Responses", null, outgoingProxyResponseRecipePanel, "Outgoing responses from Burp.");
        tabbedPane.addTab("Formatting", null, formatRecipePanel, "Formatting for messages.");
        this.add(tabbedPane);
    }

    public RecipePanel getIncomingHttpResponseRecipePanel() {
        return this.incomingHttpResponseRecipePanel;
    }
    
    public RecipePanel getIncomingProxyRequestRecipePanel() {
        return this.incomingProxyRequestRecipePanel;
    }

    public RecipePanel getOutgoingHttpRequestRecipePanel() {
        return this.outgoingHttpRequestRecipePanel;
    }
    
    public RecipePanel getOutgoingProxyResponseRecipePanel() {
        return this.outgoingProxyResponseRecipePanel;
    }

    public RecipePanel getFormatRecipePanel() {
        return this.formatRecipePanel;
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("CSTC");
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        View view = new View();

        frame.setContentPane(view);
        frame.setSize(800, 600);
        frame.setVisible(true);
//        frame.setExtendedState(java.awt.Frame.MAXIMIZED_BOTH);
    }

    public void updateInactiveWarnings() {
        incomingHttpResponseRecipePanel.showInactiveWarning();
        for(Boolean b : BurpUtils.getInstance().getFilterState().getIncomingHttpResponseFilterSettings().values()){
            if(b == true)
                incomingHttpResponseRecipePanel.hideInactiveWarning();
        }
        
        incomingProxyRequestRecipePanel.showInactiveWarning();
        for(Boolean b : BurpUtils.getInstance().getFilterState().getIncomingProxyRequestFilterSettings().values()){
            if(b == true)
                incomingProxyRequestRecipePanel.hideInactiveWarning();
        }

        outgoingHttpRequestRecipePanel.showInactiveWarning();
        for(Boolean b : BurpUtils.getInstance().getFilterState().getOutgoingHttpRequestFilterSettings().values()){
            if(b == true)
                outgoingHttpRequestRecipePanel.hideInactiveWarning();
        }
        
        outgoingProxyResponseRecipePanel.showInactiveWarning();
        for(Boolean b : BurpUtils.getInstance().getFilterState().getOutgoingProxyResponseFilterSettings().values()){
            if(b == true)
                outgoingProxyResponseRecipePanel.hideInactiveWarning();
        }
    }

    public void preventRaceConditionOnVariables() {
        incomingHttpResponseRecipePanel.disableAutobakeIfFilterActive();
        incomingProxyRequestRecipePanel.disableAutobakeIfFilterActive();
        outgoingHttpRequestRecipePanel.disableAutobakeIfFilterActive();
        outgoingProxyResponseRecipePanel.disableAutobakeIfFilterActive();
        formatRecipePanel.disableAutobakeIfFilterActive();
    }
}
