package de.usd.cstchef.view;

import java.awt.BorderLayout;
import java.awt.Color;
import java.security.Security;
import java.util.ArrayList;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.WindowConstants;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import burp.BurpExtender;
import burp.BurpUtils;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.view.filter.FilterState;
import de.usd.cstchef.view.filter.FilterState.BurpOperation;
import de.usd.cstchef.view.ui.ButtonTabComponent;
import de.usd.cstchef.view.ui.ButtonType;

public class View extends JPanel {

    private ArrayList<RecipePanel> recipePanels = new ArrayList<RecipePanel>();

    private JTabbedPane tabbedPane = new JTabbedPane();

    private String[] recipePanelNames = { "Outgoing Requests", "Incoming Responses", "Formatting" };

    public View(){
        this(new FilterState());
    }

    public View(FilterState state) {
        Security.addProvider(new BouncyCastleProvider());

        this.setLayout(new BorderLayout());
        //JTabbedPane tabbedPane = new JTabbedPane();

        recipePanels.add(new RecipePanel(BurpOperation.OUTGOING, recipePanelNames[0]));
        recipePanels.add(new RecipePanel(BurpOperation.INCOMING, recipePanelNames[1]));
        recipePanels.add(new RecipePanel(BurpOperation.FORMAT, recipePanelNames[2]));

        
        ButtonTabComponent.initPopUpMenu(this, tabbedPane);

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

    public JTabbedPane getTabbedPane() {
        return this.tabbedPane;
    }

    public void setupTabButtonsAfterRestore() {
        for(int i = recipePanels.size() - 1; i >= 0; i--) {
            if(i == recipePanels.size() - 1) {
                if(i == 2) {
                    initTabButton(i, ButtonType.ADD, recipePanels.get(i).getRecipeName());
                    return;
                }
                else {
                    initTabButton(i, ButtonType.CLOSEANDADD, recipePanels.get(i).getRecipeName());
                }
            }
            else if(i > 2) {
                initTabButton(i, ButtonType.CLOSE, recipePanels.get(i).getRecipeName());
            }
        }
    }

    public void clearRecipePanels() {
        recipePanels.clear();
        tabbedPane.removeAll();
    }

    public void removeRecipePanel(int i) {
        recipePanels.remove(i);
    }

    public void addRecipePanel(RecipePanel recipePanel) {
        recipePanels.add(recipePanel);
        tabbedPane.add(recipePanel.getRecipeName(), recipePanel);

        tabbedPane.setBackgroundAt(recipePanels.size() - 1, getColor(recipePanel.getOperation()));
    }

    public int getNumOfRecipePanels() {
        return recipePanels.size();
    }

    public RecipePanel getRecipePanelAtIndex(int n) {
        return recipePanels.get(n);
    }

    public void initTabButton(int i, ButtonType buttonType, String title) {
        tabbedPane.setTabComponentAt(i,
                 new ButtonTabComponent(this, buttonType, title));
    }

    public Color getColor(BurpOperation operation) {
        if(operation.equals(BurpOperation.OUTGOING)) {
            return new Color(0, 255, 255, 75);
        }
        else if(operation.equals(BurpOperation.INCOMING)) {
            return new Color(255, 95, 31, 75);
        }
        else {
            return new Color(0, 0, 0, 0);
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

        for(int i = 0; i < recipePanels.size(); i++) {
            if(!recipePanels.get(i).getOperation().equals(BurpOperation.FORMAT)) {
                recipePanels.get(i).showInactiveWarning();
                for(Boolean b : BurpUtils.getInstance().getFilterState().getOutgoingFilterSettings().values()){
                    if(b == true)
                        recipePanels.get(i).hideInactiveWarning();
                }
            }
        }
    }

    public void preventRaceConditionOnVariables() {

        for(int i = 0; i < recipePanels.size(); i++) {
            recipePanels.get(i).disableAutobakeIfFilterActive();
        }
    }

    public void saveRecipePanelChanges() {
        if (!BurpUtils.getInstance().getApi().burpSuite().version().edition().equals(BurpSuiteEdition.COMMUNITY_EDITION)) {
            PersistedObject savedState = BurpUtils.getInstance().getApi().persistence().extensionData();
            PersistedList<String> listOfRecipePanels = PersistedList.persistedStringList();
            for(int i = 0; i < recipePanels.size(); i++) {
                listOfRecipePanels.add(getRecipePanelAtIndex(i).getRecipeName());
                listOfRecipePanels.add(getRecipePanelAtIndex(i).getOperation().toString());
            }
            savedState.setStringList("listOfRecipePanels", listOfRecipePanels);
        }
    }
}
