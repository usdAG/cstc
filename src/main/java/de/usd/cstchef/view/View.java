package de.usd.cstchef.view;

import java.awt.BorderLayout;
import java.awt.Color;
import java.security.Security;
import java.util.ArrayList;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.WindowConstants;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import burp.BurpUtils;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.view.filter.FilterState;
import de.usd.cstchef.view.filter.FilterState.BurpOperation;
import de.usd.cstchef.view.ui.ButtonTabComponent;
import de.usd.cstchef.view.ui.ButtonType;

public class View extends JPanel {

    private static ArrayList<RecipePanel> recipePanels = new ArrayList<RecipePanel>();

    public static JTabbedPane tabbedPane = new JTabbedPane();

    public static String[] recipePanelNames = { "Outgoing Requests", "Incoming Responses", "Formatting" };

    public View(){
        this(new FilterState());
    }

    public View(FilterState state) {
        Security.addProvider(new BouncyCastleProvider());

        this.setLayout(new BorderLayout());
        //JTabbedPane tabbedPane = new JTabbedPane();

        recipePanels.add(new RecipePanel(BurpOperation.OUTGOING, MessageType.RESPONSE, recipePanelNames[0]));
        recipePanels.add(new RecipePanel(BurpOperation.INCOMING, MessageType.REQUEST, recipePanelNames[1]));
        recipePanels.add(new RecipePanel(BurpOperation.FORMAT, MessageType.RAW, recipePanelNames[2]));

        
        ButtonTabComponent.initPopUpMenu();

        for(int i = 0; i < 3; i++) {
            tabbedPane.add(recipePanels.get(i).getRecipeName(), recipePanels.get(i));
        }

        initTabButton(0, ButtonType.NONE, recipePanelNames[0]);
        initTabButton(1, ButtonType.NONE, recipePanelNames[1]);
        initTabButton(2, ButtonType.ADD, recipePanelNames[2]);
        
        tabbedPane.setBackgroundAt(0, getColor(BurpOperation.OUTGOING));
        tabbedPane.setBackgroundAt(1, getColor(BurpOperation.INCOMING));
        

        this.add(tabbedPane);
    }

    public static int getNumOfRecipePanels() {
        return recipePanels.size();
    }

    public static RecipePanel getRecipePanelAtIndex(int n) {
        return recipePanels.get(n);
    }

    public static void initTabButton(int i, ButtonType buttonType, String title) {
        tabbedPane.setTabComponentAt(i,
                 new ButtonTabComponent(tabbedPane, buttonType, title));
    }

    public static Color getColor(BurpOperation operation) {
        if(operation == BurpOperation.OUTGOING) {
            return new Color(0, 255, 255, 75);
        }
        else {
            return new Color(255, 95, 31, 75);
        }
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

        for(int i = 0; i < View.recipePanels.size(); i++) {
            if(!View.recipePanels.get(i).getOperation().equals(BurpOperation.FORMAT)) {
                View.recipePanels.get(i).showInactiveWarning();
                for(Boolean b : BurpUtils.getInstance().getFilterState().getOutgoingFilterSettings().values()){
                    if(b == true)
                        View.recipePanels.get(i).hideInactiveWarning();
                }
            }
        }
    }

    public void preventRaceConditionOnVariables() {

        for(int i = 0; i < View.recipePanels.size(); i++) {
            View.recipePanels.get(i).disableAutobakeIfFilterActive();
        }
    }
}
