package com.encrypt.service.impl;

import com.encrypt.service.EncryptService;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@Service
public class EncryptServiceImpl implements EncryptService {

    @Override
    public String getSha3_256(String param1, String param2) {
        byte[] rdnParam2 = param2.getBytes(StandardCharsets.UTF_8);
        byte[] salt = generateSalt();
        byte[] hashValue = encryptSHA3_256(param1, salt, rdnParam2);
        byte[] dataResult = new byte[32 + salt.length + rdnParam2.length];
        System.arraycopy(hashValue, 0, dataResult, 0, 32);
        System.arraycopy(salt, 0, dataResult, 32, salt.length);
        System.arraycopy(rdnParam2, 0, dataResult, 32 + salt.length, rdnParam2.length);
        String encryptStr = Base64.getEncoder().encodeToString(dataResult);

        return encryptStr;
    }

    @Override
    public String getHmac(Map<String, String> reqMap) throws Exception {
        ApiParameter parameters = new ApiParameter();
        parameters.putParameter("param3", reqMap.get("param3"));
        parameters.putParameter("param4", reqMap.get("param4"));

        String param5 = reqMap.get("param5");
        String hmac = parameters.calculateRFC2104HMAC(parameters.toPlantString(), param5);

        return hmac;
    }

    public byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[8];
        random.nextBytes(salt);
        return salt;
    }

    public byte[] encryptSHA3_256(String param1, byte[] salt, byte[] param2) {
        MessageDigest digest = null;

        try {
            digest = MessageDigest.getInstance("SHA3-256");
            digest.update(param1.getBytes(StandardCharsets.UTF_8));
            digest.update(salt);
            digest.update(param2);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return digest.digest();
    }

    private class ApiParameter {
        private List<Map.Entry<String, String>> origParameter;

        private final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

        public ApiParameter() {
            this.origParameter = new ArrayList<>();
        }

        public void putParameter(String name, String val) {
            Map.Entry<String, String> pair = new AbstractMap.SimpleEntry<>(name, val);
            this.origParameter.add(pair);
        }

        public String toPlantString() {
            StringBuilder s = new StringBuilder();
            for (Map.Entry<String, String> e : origParameter) {
                s.append(e.getKey());
                s.append("=");
                s.append(e.getValue());
                s.append("&");
            }
            return s.substring(0, s.toString().length() - 1);
        }

        public String calculateRFC2104HMAC(String data, String apiKey) throws NoSuchAlgorithmException, InvalidKeyException {
            SecretKeySpec signingKey = new SecretKeySpec(apiKey.getBytes(), HMAC_SHA256_ALGORITHM);
            Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            mac.init(signingKey);
            byte[] rawHmac = mac.doFinal(data.getBytes());
            String baseHmac = Base64.getEncoder().encodeToString(rawHmac);

            return URLEncoder.encode(baseHmac, StandardCharsets.UTF_8);
        }
    }
}
