package burp;


import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import de.usd.cstchef.view.View;

public class BurpExtender implements BurpExtension {

    private final String extensionName = "CSTC";
    private View view;
    private static MontoyaApi api;


    @Override
    public void initialize(MontoyaApi api) {
        BurpExtender.api = api;
        api.extension().setName(extensionName);
        api.userInterface().registerContextMenuItemsProvider(new CstcContextMenuItemsProvider(api, view));
        api.http().registerHttpHandler(new CstcHttpHandler(view));
        // TODO Register messageeditor
        BurpUtils.getInstance().init(api);
    }

    // @Override
    // public Component getUiComponent() {
    //     this.view = new View();
    //     return this.view;
    // }


    // @Override
    // public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
    //     RecipePanel requestFormatPanel = this.view.getOutgoingRecipePanel();
    //     // TODO do we need the format panel or do we want to use the incoming recipe?
    //     RecipePanel responseFormatPanel = this.view.getFormatRecipePanel();
    //     return new FormatTab(requestFormatPanel, responseFormatPanel, editable);
    // }


    
}
