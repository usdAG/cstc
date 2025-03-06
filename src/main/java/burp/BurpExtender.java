package burp;

import java.awt.TrayIcon.MessageType;
import java.util.ArrayList;

import com.fasterxml.jackson.databind.ObjectMapper;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import de.usd.cstchef.view.RecipePanel;
import de.usd.cstchef.view.RequestFilterDialog;
import de.usd.cstchef.view.View;
import de.usd.cstchef.view.filter.FilterState;
import de.usd.cstchef.view.filter.FilterState.BurpOperation;
import de.usd.cstchef.view.ui.ButtonTabComponent;

public class BurpExtender implements BurpExtension {

    private final String extensionName = "CSTC";
    private View view;

    @Override
    public void initialize(MontoyaApi api) {
        BurpUtils.getInstance().init(api);
        this.view = new View();
        BurpUtils.getInstance().setView(view);
        api.extension().setName(extensionName);
        api.userInterface().registerContextMenuItemsProvider(new CstcContextMenuItemsProvider(api, view));
        api.http().registerHttpHandler(new CstcHttpHandler(view));
        api.userInterface().registerSuiteTab(extensionName, view);
        api.userInterface().registerHttpRequestEditorProvider(new MyHttpRequestEditorProvider(view));
        api.userInterface().registerHttpRequestEditorProvider(new MyHttpRequestEditorProviderFormatting(view));
        api.userInterface().registerHttpResponseEditorProvider(new MyHttpResponseEditorProviderFormatting(view));

        if (!api.burpSuite().version().edition().equals(BurpSuiteEdition.COMMUNITY_EDITION)) {
            PersistedObject persistence = api.persistence().extensionData();
            restoreRecipePanels(persistence);
            restoreFilterState(persistence);
            restoreRecipe(persistence);
        }
        view.updateInactiveWarnings();
    }

    private void restoreRecipe(PersistedObject persistence) {
        try {

            for(int i = 0; i < view.getNumOfRecipePanels(); i++) {
                view.getRecipePanelAtIndex(i).restoreState(persistence.getString(view.getRecipePanelAtIndex(i).getRecipeName()));
            }
        } catch (Exception e) {
            Logger.getInstance().log(
                    "Could not restore the recipe for one or multiple panels. If this is the first time using CSTC in a project, you can ignore this message.");
        }
    }

    private void restoreFilterState(PersistedObject persistence) {
        try {
            BurpUtils.getInstance().setFilterState(new ObjectMapper().readValue(persistence.getString("FilterState"), FilterState.class));
            RequestFilterDialog.getInstance().updateFilterSettings();
            view.preventRaceConditionOnVariables();
        } catch (Exception e) {
            Logger.getInstance().log(
                    "Could not restore the filter state. If this is the first time using CSTC in a project, you can ignore this message. " + e.getMessage());
        }
    }

    private void restoreRecipePanels(PersistedObject persistence) {
        try {
            PersistedList<String> listOfRecipePanels = persistence.getStringList("listOfRecipePanels");
            if(listOfRecipePanels.equals(null)) {
                throw new NullPointerException("listOfRecipePanels is null.");
            }
            view.clearRecipePanels();
            
            for(int i = 0; i < listOfRecipePanels.size() - 1; i++) {
                String operation = listOfRecipePanels.get(i+1);
                BurpOperation burpOperation = operation.equals("Outgoing") ? BurpOperation.OUTGOING : operation.equals("Incoming") ? BurpOperation.INCOMING : BurpOperation.FORMAT;
                view.addRecipePanel(new RecipePanel(burpOperation, listOfRecipePanels.get(i)));
                i++;
            }

            ButtonTabComponent.updateIndexOfLastComp(view.getNumOfRecipePanels() - 1);
            view.setupTabButtonsAfterRestore();
        } catch (Exception e) {
            Logger.getInstance().log(
                    "Could not restore all recipe panels. If this is the first time using CSTC in a project, you can ignore this message.");
        }
    }
}
