package seguranca;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utilitário criptográfico para o Envelope Criptográfico Híbrido (AES + HMAC + RSA).
 * Garante:
 * - Confidencialidade: Criptografia simétrica AES sobre a mensagem.
 * - Integridade: Hash HMAC (HmacSHA256) calculado sobre a mensagem criptografada.
 * - Autenticidade e Irretratabilidade (Assinatura Digital): Hash HMAC criptografado com
 *   a chave privada RSA do emissor e validado com a chave pública RSA do emissor.
 */
public class CriptoUtils {

    private static final String ALGORITMO_AES = "AES";
    private static final String TRANSFORMACAO_AES = "AES/ECB/PKCS5Padding";
    private static final String ALGORITMO_HMAC = "HmacSHA256";
    private static final String ALGORITMO_RSA = "RSA";
    private static final String TRANSFORMACAO_RSA = "RSA/ECB/PKCS1Padding";

    public static SecretKey gerarChaveAES() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITMO_AES);
            keyGen.init(128);
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar chave simétrica AES: " + e.getMessage(), e);
        }
    }

    public static SecretKey gerarChaveHMAC() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITMO_HMAC);
            keyGen.init(256);
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar chave HMAC: " + e.getMessage(), e);
        }
    }

    public static KeyPair gerarParChavesRSA() {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(ALGORITMO_RSA);
            keyPairGen.initialize(2048);
            return keyPairGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar par de chaves RSA: " + e.getMessage(), e);
        }
    }

    public static String cifrarAES(String mensagem, SecretKey chaveSimetrica) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITMO_AES);
            cipher.init(Cipher.ENCRYPT_MODE, chaveSimetrica);
            byte[] textoCifrado = cipher.doFinal(mensagem.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(textoCifrado);
        } catch (Exception e) {
            throw new SecurityException("Erro ao cifrar mensagem com AES: " + e.getMessage(), e);
        }
    }

    public static String decifrarAES(String mensagemCifradaB64, SecretKey chaveSimetrica) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITMO_AES);
            cipher.init(Cipher.DECRYPT_MODE, chaveSimetrica);
            byte[] bytesCifrados = Base64.getDecoder().decode(mensagemCifradaB64);
            byte[] textoPlano = cipher.doFinal(bytesCifrados);
            return new String(textoPlano, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new SecurityException("Erro ao decifrar mensagem com AES: " + e.getMessage(), e);
        }
    }

    public static String calcularHMAC(String mensagemCifradaB64, SecretKey chaveHMAC) {
        try {
            Mac mac = Mac.getInstance(ALGORITMO_HMAC);
            mac.init(chaveHMAC);
            byte[] hmacBytes = mac.doFinal(mensagemCifradaB64.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hmacBytes);
        } catch (Exception e) {
            throw new SecurityException("Erro ao calcular hash HMAC: " + e.getMessage(), e);
        }
    }

    public static String criptografarHmacComChavePrivadaRSA(String hashHmacB64, PrivateKey chavePrivadaEmissor) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITMO_RSA);
            cipher.init(Cipher.ENCRYPT_MODE, chavePrivadaEmissor);
            byte[] assinaturaBytes = cipher.doFinal(hashHmacB64.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(assinaturaBytes);
        } catch (Exception e) {
            throw new SecurityException("Erro ao assinar HMAC com chave privada RSA: " + e.getMessage(), e);
        }
    }

    public static String descriptografarHmacComChavePublicaRSA(String assinaturaRsaB64, PublicKey chavePublicaEmissor) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITMO_RSA);
            cipher.init(Cipher.DECRYPT_MODE, chavePublicaEmissor);
            byte[] assinaturaBytes = Base64.getDecoder().decode(assinaturaRsaB64);
            byte[] hashRecuperado = cipher.doFinal(assinaturaBytes);
            return new String(hashRecuperado, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new SecurityException("Falha na validação RSA com a chave pública do emissor: " + e.getMessage(), e);
        }
    }

    public static boolean validarHashes(String hashExtraidoDaAssinatura, String hashCalculadoLocalmente) {
        if (hashExtraidoDaAssinatura == null || hashCalculadoLocalmente == null) {
            return false;
        }
        return MessageDigest.isEqual(
                hashExtraidoDaAssinatura.getBytes(StandardCharsets.UTF_8),
                hashCalculadoLocalmente.getBytes(StandardCharsets.UTF_8)
        );
    }

    // SERIALIZAÇÃO BASE64 DE CHAVES

    public static String chaveSimetricaParaBase64(SecretKey chave) {
        return Base64.getEncoder().encodeToString(chave.getEncoded());
    }

    public static SecretKey chaveAESDeBase64(String base64) {
        byte[] decoded = Base64.getDecoder().decode(base64);
        return new SecretKeySpec(decoded, 0, decoded.length, ALGORITMO_AES);
    }

    public static SecretKey chaveHMACDeBase64(String base64) {
        byte[] decoded = Base64.getDecoder().decode(base64);
        return new SecretKeySpec(decoded, 0, decoded.length, ALGORITMO_HMAC);
    }

    public static String chavePublicaParaBase64(PublicKey chavePublica) {
        return Base64.getEncoder().encodeToString(chavePublica.getEncoded());
    }

    public static PublicKey chavePublicaDeBase64(String base64) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITMO_RSA);
            return keyFactory.generatePublic(spec);
        } catch (Exception e) {
            throw new SecurityException("Chave pública RSA inválida: " + e.getMessage(), e);
        }
    }

    public static String resumirBase64(String b64) {
        if (b64 == null) {
            return "null";
        }
        if (b64.length() <= 18) {
            return b64;
        }
        return b64.substring(0, 12) + "..." + b64.substring(b64.length() - 6);
    }
}
