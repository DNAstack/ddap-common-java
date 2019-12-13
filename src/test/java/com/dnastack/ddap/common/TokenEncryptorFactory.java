package com.dnastack.ddap.common;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Component;

@Component
public class TokenEncryptorFactory {

    @Getter
    private final TextEncryptor encryptor;

    public TokenEncryptorFactory(@Value("${ddap.cookies.encryptor.password}") String encryptorPassword,
                                 @Value("${ddap.cookies.encryptor.salt}") String encryptorSalt) {
        this.encryptor = Encryptors.text(encryptorPassword, encryptorSalt);
    }

}
