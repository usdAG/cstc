package de.usd.cstchef.operations.compression;

import java.util.zip.Inflater;

import burp.api.montoya.core.ByteArray;

import java.io.ByteArrayOutputStream;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Inflate", category = OperationCategory.COMPRESSION, description = "Inflate input string")

public class Inflate extends Operation {

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        Inflater inflater = new Inflater();
        inflater.setInput(input.getBytes());

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(input.length());

        byte[] buffer = new byte[1024];
        while( !inflater.finished() ) {
            int count = inflater.inflate(buffer);
            outputStream.write(buffer, 0, count);
        }

        outputStream.close();
        return factory.createByteArray(outputStream.toByteArray());
    }
}
