package burp;

import com.fasterxml.jackson.databind.ObjectMapper;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.persistence.PersistedObject;
import de.usd.cstchef.view.RequestFilterDialog;
import de.usd.cstchef.view.View;
import de.usd.cstchef.view.filter.FilterState;

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
            restoreFilterState(persistence);
            restoreRecipe(persistence);
        }
        view.updateInactiveWarnings();
    }

    private void restoreRecipe(PersistedObject persistence) {
        try {

            for(int i = 0; i < View.getNumOfRecipePanels(); i++) {
                View.getRecipePanelAtIndex(i).restoreState(persistence.getString(View.getRecipePanelAtIndex(i).getRecipeName()));
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
}
