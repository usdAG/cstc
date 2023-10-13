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
        BurpUtils.getInstance().init(api);
        BurpExtender.api = api;
        this.view = new View();
        api.extension().setName(extensionName);
        api.userInterface().registerContextMenuItemsProvider(new CstcContextMenuItemsProvider(api, view));
        api.http().registerHttpHandler(new CstcHttpHandler(view));
        api.userInterface().registerSuiteTab(extensionName, view);
        // api.userInterface().registerHttpRequestEditorProvider(new MyHttpRequestEditorProvider(view));
    }
    
}
