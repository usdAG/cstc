package burp;

import com.fasterxml.jackson.databind.ObjectMapper;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.persistence.PersistedObject;
import de.usd.cstchef.view.RequestFilterDialog;
import de.usd.cstchef.view.View;
import de.usd.cstchef.view.filter.FilterState;
import de.usd.cstchef.view.filter.FilterState.BurpOperation;

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
        api.proxy().registerRequestHandler(new CstcProxyRequestHandler(view));
        api.proxy().registerResponseHandler(new CstcProxyResponseHandler(view));
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
            this.view.getFormatRecipePanel().restoreState(persistence.getString(BurpOperation.FORMAT + "Recipe"));
            this.view.getIncomingHttpResponseRecipePanel().restoreState(persistence.getString(BurpOperation.INCOMING_HTTP_RESPONSE + "Recipe"));
            this.view.getIncomingProxyRequestRecipePanel().restoreState(persistence.getString(BurpOperation.INCOMING_PROXY_REQUEST + "Recipe"));
            this.view.getOutgoingHttpRequestRecipePanel().restoreState(persistence.getString(BurpOperation.OUTGOING_HTTP_REQUEST + "Recipe"));
            this.view.getOutgoingProxyResponseRecipePanel().restoreState(persistence.getString(BurpOperation.OUTGOING_PROXY_RESPONSE + "Recipe"));
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
