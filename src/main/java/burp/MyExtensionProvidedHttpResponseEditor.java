package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.view.View;

import java.awt.*;

public class MyExtensionProvidedHttpResponseEditor implements ExtensionProvidedHttpResponseEditor
{
    private final RawEditor requestEditor;
    private HttpRequestResponse requestResponse;
    private final MontoyaApi api;
    private final View view;

    MyExtensionProvidedHttpResponseEditor(EditorCreationContext creationContext, View view)
    {
        this.api = BurpUtils.getInstance().getApi();
        this.view = view;
        requestEditor = api.userInterface().createRawEditor();
    }

    @Override
    public HttpResponse getResponse()
    {
        return requestResponse.response();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse)
    {
        ByteArray result = view.getIncomingRecipePanel().bake(requestResponse.response().toByteArray(), MessageType.RESPONSE);
        this.requestEditor.setContents(result);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse)
    {
        return requestResponse.response() != null;
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