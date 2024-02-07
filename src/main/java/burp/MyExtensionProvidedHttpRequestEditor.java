package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.view.View;

import java.awt.*;

public class MyExtensionProvidedHttpRequestEditor implements ExtensionProvidedHttpRequestEditor
{
    private final RawEditor requestEditor;
    private HttpRequestResponse requestResponse;
    private final MontoyaApi api;
    private final View view;

    MyExtensionProvidedHttpRequestEditor(EditorCreationContext creationContext, View view)
    {
        this.api = BurpUtils.getInstance().getApi();
        this.view = view;
        requestEditor = api.userInterface().createRawEditor();
    }

    @Override
    public HttpRequest getRequest()
    {
        return requestResponse.request();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse)
    {
        ByteArray result = view.getOutgoingRecipePanel().bake(requestResponse.request().toByteArray(), MessageType.REQUEST);
        this.requestEditor.setContents(result);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse)
    {
        return requestResponse.request() != null;
    }

    @Override
    public String caption()
    {
        return "CSTC";
    }

    @Override
    public Component uiComponent()
    {
        return requestEditor.uiComponent();
    }

    @Override
    public Selection selectedData()
    {
        return requestEditor.selection().isPresent() ? requestEditor.selection().get() : null;
    }

    @Override
    public boolean isModified()
    {
        return requestEditor.isModified();
    }
}