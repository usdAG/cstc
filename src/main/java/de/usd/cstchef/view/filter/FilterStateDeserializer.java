package de.usd.cstchef.view.filter;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.KeyDeserializer;

public class FilterStateDeserializer extends KeyDeserializer {

  @Override
  public Filter deserializeKey(
    String key, 
    DeserializationContext ctxt) throws IOException, 
    JsonProcessingException {
      return new Filter(key);
    }
}