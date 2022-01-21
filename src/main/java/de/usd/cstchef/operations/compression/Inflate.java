package de.usd.cstchef.operations.compression;

import java.util.zip.Inflater;
import java.io.ByteArrayOutputStream;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Inflate", category = OperationCategory.COMPRESSION, description = "Inflate input string")

public class Inflate extends Operation {

    @Override
    protected byte[] perform(byte[] input) throws Exception {
        Inflater inflater = new Inflater();
        inflater.setInput(input);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(input.length);   

        byte[] buffer = new byte[1024];   
        while( !inflater.finished() ) {  
            int count = inflater.inflate(buffer);
            outputStream.write(buffer, 0, count);   
        }

        outputStream.close();
        return outputStream.toByteArray();
    }  
}
