package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import de.usd.cstchef.view.View;

class MyHttpRequestEditorProvider implements HttpRequestEditorProvider
{
    private final View view;

    MyHttpRequestEditorProvider(View view){
        this.view = view;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext)
    {
        if(creationContext.toolSource().isFromTool(ToolType.REPEATER)) {
            return new MyExtensionProvidedHttpRequestEditor(creationContext, view);
        }
        else {
            return null;
        }
    }
}