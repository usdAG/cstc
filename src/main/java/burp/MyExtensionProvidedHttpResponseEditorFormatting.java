package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.view.View;

import java.awt.*;

public class MyExtensionProvidedHttpResponseEditorFormatting implements ExtensionProvidedHttpResponseEditor
{
    private final RawEditor responseEditor;
    private HttpRequestResponse requestResponse;
    private final MontoyaApi api;
    private final View view;

    MyExtensionProvidedHttpResponseEditorFormatting(EditorCreationContext creationContext, View view)
    {
        this.api = BurpUtils.getInstance().getApi();
        this.view = view;
        responseEditor = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
    }

    @Override
    public HttpResponse getResponse()
    {
        return requestResponse.response();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse)
    {
        ByteArray result = view.getFormatRecipePanel().bake(requestResponse.response().toByteArray(), MessageType.RESPONSE);
        this.responseEditor.setContents(result);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse)
    {
        return requestResponse.response() != null;
    }

    @Override
    public String caption()
    {
        return "CSTC Formatting";
    }

    @Override
    public Component uiComponent()
    {
        return responseEditor.uiComponent();
    }

    @Override
    public Selection selectedData()
    {
        return responseEditor.selection().isPresent() ? responseEditor.selection().get() : null;
    }

    @Override
    public boolean isModified()
    {
        return responseEditor.isModified();
    }
}