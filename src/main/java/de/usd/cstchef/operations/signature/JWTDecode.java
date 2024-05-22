package de.usd.cstchef.operations.signature;

import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextField;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.swing.JComboBox;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.apache.commons.lang3.NotImplementedException;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import burp.Logger;
import burp.api.montoya.core.ByteArray;

@OperationInfos(name = "JWT Decode", category = OperationCategory.SIGNATURE, description = "Decode a given JWT payload and return its contents")
public class JWTDecode extends Operation {

	@Override
	protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {
		DecodedJWT content = JWT.decode(input.toString());		
		return factory.createByteArray(Base64.getDecoder().decode(content.getPayload()));
	}
}
