package de.usd.cstchef.operations.extractors;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.Reader;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "HTTP URI", category = OperationCategory.EXTRACTORS, description = "Extracts the URI of a HTTP request.")
public class HttpUriExtractor extends Operation {

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		try {
			// Request-Line = Method SP Request-URI SP HTTP-Version CRLF
			Reader in = new InputStreamReader(new ByteArrayInputStream(input));
			BufferedReader reader = new BufferedReader(in);
			String requestLine = reader.readLine();
			String[] parts = requestLine.split(" ");
			return parts[1].getBytes();
		} catch (Exception e) {
			throw new IllegalArgumentException("Provided input is not a valid http request.");
		}
	}
}