package de.usd.cstchef.view;

import java.awt.BorderLayout;
import java.security.Security;
import java.util.LinkedHashMap;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.WindowConstants;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.usd.cstchef.FilterState;
import de.usd.cstchef.FilterState.BurpOperation;

public class View extends JPanel {

    private RecipePanel incomingRecipePanel;
    private RecipePanel outgoingRecipePanel;
    private RecipePanel formatRecipePanel;
    private FilterState filterState;

    public View() {
        Security.addProvider(new BouncyCastleProvider());

        this.setLayout(new BorderLayout());
        JTabbedPane tabbedPane = new JTabbedPane();

        filterState = new FilterState();

        incomingRecipePanel = new RecipePanel(BurpOperation.INCOMING, false, filterState);
        outgoingRecipePanel = new RecipePanel(BurpOperation.OUTGOING, true, filterState);
        formatRecipePanel = new RecipePanel(BurpOperation.FORMAT, true, filterState);

        tabbedPane.addTab("Outgoing Requests", null, outgoingRecipePanel, "Outgoing requests from the browser, the repeater or another tool.");
        tabbedPane.addTab("Incoming Responses", null, incomingRecipePanel, "Responses from the server.");
        tabbedPane.addTab("Formating", null, formatRecipePanel, "Formating for messages.");
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

    public FilterState getFilterState(){
        return filterState;
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
}
