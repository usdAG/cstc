package de.usd.cstchef.operations.signature;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

import java.util.Base64;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

import burp.api.montoya.core.ByteArray;

@OperationInfos(name = "JWT Decode", category = OperationCategory.SIGNATURE, description = "Decode a given JWT payload and return its contents")
public class JWTDecode extends Operation {

	@Override
	protected ByteArray perform(ByteArray input) throws Exception {
		DecodedJWT content = JWT.decode(input.toString());		
		return factory.createByteArray(Base64.getDecoder().decode(content.getPayload()));
	}
}
