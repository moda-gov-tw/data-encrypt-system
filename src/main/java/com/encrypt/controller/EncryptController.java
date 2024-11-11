package com.encrypt.controller;

import com.encrypt.service.EncryptService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class EncryptController {

    @Autowired
    EncryptService encryptService;

    @PostMapping("/sha3_256")
    public ResponseEntity<String> getSha3(@RequestBody Map<String, String> request) {
        System.out.println("Call Sha3-256");
        String param1 = request.get("param1");
        String param2 = request.get("param2");
        String encryptStr = encryptService.getSha3_256(param1, param2);

        System.out.println("Success");
        System.out.println("The String is :" + encryptStr);
        return ResponseEntity.ok(encryptStr);
    }

    @PostMapping("/hmac")
    public ResponseEntity<String> getHmac(@RequestBody Map<String, String> reqMap) throws Exception {
        System.out.println("Call Hmac");
        String encryptStr = encryptService.getHmac(reqMap);

        System.out.println("Success");
        System.out.println("The String is :" + encryptStr);
        return ResponseEntity.ok((encryptStr));
    }

}
