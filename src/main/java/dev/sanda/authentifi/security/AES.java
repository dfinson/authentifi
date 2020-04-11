package dev.sanda.authentifi.security;

import dev.sanda.jwtauthtemplate.config.AuthenticationServerConfiguration;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Slf4j
@Component
public class AES {
    @Autowired
    private AuthenticationServerConfiguration configuration;
    private static final IvParameterSpec ivspec = new IvParameterSpec(new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    public String encrypt(String strToEncrypt)
    {
        try
        {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            val spec = new PBEKeySpec(configuration.aesSecretKey().toCharArray(), configuration.aesSalt().getBytes(), 65536, 256);
            val tmp = factory.generateSecret(spec);
            val secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        }
        catch (Exception e) {
            log.error("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public String decrypt(String strToDecrypt) {
        try
        {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            val spec = new PBEKeySpec(configuration.aesSecretKey().toCharArray(), configuration.aesSalt().getBytes(), 65536, 256);
            val tmp = factory.generateSecret(spec);
            val secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
            val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        }
        catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
}