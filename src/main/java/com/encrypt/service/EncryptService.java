package com.encrypt.service;

import java.util.Map;

public interface EncryptService {

    String getSha3_256(String param1, String param2);

    String getHmac(Map<String, String> reqMap) throws Exception;
}
