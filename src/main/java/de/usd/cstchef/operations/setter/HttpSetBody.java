package de.usd.cstchef.operations.setter;

import java.util.Arrays;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.FormatTextField;

@OperationInfos(name = "HTTP Body", category = OperationCategory.SETTER, description = "Set the HTTP body to the specified value.")
public class HttpSetBody extends Operation {

    private FormatTextField replacementTxt;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {
        MontoyaApi api = BurpUtils.getInstance().getApi();
        int bodyOffset = HttpRequest.httpRequest(input).bodyOffset();

        ByteArray noBody = BurpUtils.subArray(input, 0, bodyOffset);
        ByteArray newBody = replacementTxt.getText();
        ByteArray newRequest = noBody.withAppended(newBody);

        return newRequest;
    }

    @Override
    public void createUI() {
        this.replacementTxt = new FormatTextField();
        this.addUIElement("Body", this.replacementTxt);
    }

}
