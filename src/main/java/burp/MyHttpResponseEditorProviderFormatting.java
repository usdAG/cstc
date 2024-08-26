package burp;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import de.usd.cstchef.view.View;

class MyHttpResponseEditorProviderFormatting implements HttpResponseEditorProvider
{
    private final View view;

    MyHttpResponseEditorProviderFormatting(View view){
        this.view = view;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext)
    {
        // everywhere but in CSTC itself
        if(!creationContext.toolSource().isFromTool(ToolType.EXTENSIONS)) {
            return new MyExtensionProvidedHttpResponseEditorFormatting(creationContext, view);
        }
        else {
            return null;
        }
    }
}