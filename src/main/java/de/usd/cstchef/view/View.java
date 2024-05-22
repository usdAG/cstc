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

    private RecipePanel incomingRecipePanel;
    private RecipePanel outgoingRecipePanel;
    private RecipePanel formatRecipePanel;

    public View(){
        this(new FilterState());
    }

    public View(FilterState state) {
        Security.addProvider(new BouncyCastleProvider());

        this.setLayout(new BorderLayout());
        JTabbedPane tabbedPane = new JTabbedPane();

        incomingRecipePanel = new RecipePanel(BurpOperation.INCOMING, MessageType.RESPONSE);
        outgoingRecipePanel = new RecipePanel(BurpOperation.OUTGOING, MessageType.REQUEST);
        formatRecipePanel = new RecipePanel(BurpOperation.FORMAT, MessageType.RAW);

        tabbedPane.addTab("Outgoing Requests", null, outgoingRecipePanel, "Outgoing requests from the browser, the repeater or another tool.");
        tabbedPane.addTab("Incoming Responses", null, incomingRecipePanel, "Responses from the server.");
        tabbedPane.addTab("Formatting", null, formatRecipePanel, "Formatting for messages.");
        this.add(tabbedPane);
    }

    public RecipePanel getIncomingRecipePanel() {
        return this.incomingRecipePanel;
    }

    public RecipePanel getOutgoingRecipePanel() {
        return this.outgoingRecipePanel;
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
        incomingRecipePanel.showInactiveWarning();
        for(Boolean b : BurpUtils.getInstance().getFilterState().getIncomingFilterSettings().values()){
            if(b == true)
                incomingRecipePanel.hideInactiveWarning();
        }

        outgoingRecipePanel.showInactiveWarning();
        for(Boolean b : BurpUtils.getInstance().getFilterState().getOutgoingFilterSettings().values()){
            if(b == true)
                outgoingRecipePanel.hideInactiveWarning();
        }
    }
}
