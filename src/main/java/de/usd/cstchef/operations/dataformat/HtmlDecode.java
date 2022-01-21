package de.usd.cstchef.operations.dataformat;

import java.nio.charset.StandardCharsets;

import org.apache.commons.text.StringEscapeUtils;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTML Decode", category = OperationCategory.DATAFORMAT, description = "HTML Decode")
public class HtmlDecode extends Operation {

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		
		String tmp = new String(input, StandardCharsets.ISO_8859_1);
		tmp = StringEscapeUtils.unescapeHtml4(tmp);
		return tmp.getBytes(StandardCharsets.ISO_8859_1);
	}

}
