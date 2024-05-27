package de.usd.cstchef.operations.dataformat;

import burp.api.montoya.core.ByteArray;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import de.usd.cstchef.Utils;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;

@Operation.OperationInfos(name = "Pretty JSON", category = OperationCategory.DATAFORMAT, description = "Format JSON Data.")
public class FormatJSON extends Operation {
	@Override
	protected ByteArray perform(ByteArray input, Utils.MessageType messageType) throws Exception {
		try {
			ObjectMapper objectMapper = new ObjectMapper();
			objectMapper.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
			JsonNode jsonNode = objectMapper.readTree(input.toString());
			return ByteArray.byteArray(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonNode));
		} catch (Exception e2) {
			return input;
		}
	}
}
