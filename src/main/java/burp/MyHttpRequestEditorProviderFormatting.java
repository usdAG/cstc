package burp;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import de.usd.cstchef.view.View;

class MyHttpRequestEditorProviderFormatting implements HttpRequestEditorProvider
{
    private final View view;

    MyHttpRequestEditorProviderFormatting(View view){
        this.view = view;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext)
    {
        // everywhere but in CSTC itself
        if(!creationContext.toolSource().isFromTool(ToolType.EXTENSIONS)) {
            return new MyExtensionProvidedHttpRequestEditorFormatting(creationContext, view);
        }
        else {
            return null;
        }
    }
}