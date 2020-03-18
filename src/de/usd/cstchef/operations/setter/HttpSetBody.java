package de.usd.cstchef.operations.setter;

import java.util.Arrays;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.FormatTextField;

@OperationInfos(name = "HTTP Set Body", category = OperationCategory.SETTER, description = "Set the HTTP body to the given value")
public class HttpSetBody extends Operation {

	private FormatTextField replacementTxt;

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		IBurpExtenderCallbacks cbs = BurpUtils.getInstance().getCallbacks();
		IRequestInfo requestInfo = cbs.getHelpers().analyzeRequest(input);
		int bodyOffset = requestInfo.getBodyOffset();

		byte[] noBody = Arrays.copyOfRange(input, 0, bodyOffset);
		byte[] newBody = replacementTxt.getText();
		byte[] newRequest = new byte[noBody.length + newBody.length];
		System.arraycopy(noBody, 0, newRequest, 0, noBody.length);
		System.arraycopy(newBody, 0, newRequest, noBody.length, newBody.length);

		return newRequest;
	}

	@Override
	public void createUI() {
		this.replacementTxt = new FormatTextField();
		this.addUIElement("Body", this.replacementTxt);
	}

}
