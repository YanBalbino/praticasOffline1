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
 * Utilitário criptográfico para o Canal Seguro e Envelope Criptográfico Híbrido (RSA + AES + HMAC).
 * Garante os 4 pilares da segurança na comunicação:
 * 1. Confidencialidade na Troca de Chaves (Assimétrica - RSA): As chaves de sessão (AES e HMAC)
 *    são cifradas com a Chave Pública RSA do destinatário e decifradas exclusivamente com a
 *    Chave Privada RSA do destinatário.
 * 2. Confidencialidade da Mensagem (Simétrica - AES): O payload da mensagem é cifrado com a
 *    chave simétrica AES compartilhada na sessão.
 * 3. Integridade (Hash de Autenticação - HMAC-SHA256): O hash HMAC é calculado sobre o payload
 *    cifrado (padrão Encrypt-then-MAC) usando a chave HMAC da sessão.
 * 4. Autenticidade e Irretratabilidade (Assinatura Digital - RSA): O hash HMAC é assinado
 *    (cifrado) com a Chave Privada RSA do emissor e verificado com a Chave Pública RSA do emissor.
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

    // =========================================================================
    // CRIPTOGRAFIA SIMÉTRICA (AES) - CONFIDENCIALIDADE DO PAYLOAD
    // =========================================================================

    public static String cifrarAES(String mensagem, SecretKey chaveSimetrica) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMACAO_AES);
            cipher.init(Cipher.ENCRYPT_MODE, chaveSimetrica);
            byte[] textoCifrado = cipher.doFinal(mensagem.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(textoCifrado);
        } catch (Exception e) {
            throw new SecurityException("Erro ao cifrar mensagem com AES: " + e.getMessage(), e);
        }
    }

    public static String decifrarAES(String mensagemCifradaB64, SecretKey chaveSimetrica) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMACAO_AES);
            cipher.init(Cipher.DECRYPT_MODE, chaveSimetrica);
            byte[] bytesCifrados = Base64.getDecoder().decode(mensagemCifradaB64);
            byte[] textoPlano = cipher.doFinal(bytesCifrados);
            return new String(textoPlano, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new SecurityException("Erro ao decifrar mensagem com AES: " + e.getMessage(), e);
        }
    }

    // =========================================================================
    // CRIPTOGRAFIA ASSIMÉTRICA (RSA) - ENCAPSULAMENTO DE CHAVES DE SESSÃO
    // =========================================================================

    /**
     * Cifra uma chave simétrica (AES ou HMAC) usando a Chave Pública RSA do destinatário.
     * Garante que apenas o detentor da Chave Privada RSA correspondente recupere a chave de sessão.
     */
    public static String cifrarChaveSimetricaComPublicaRSA(SecretKey chaveSimetrica, PublicKey chavePublicaDestinatario) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMACAO_RSA);
            cipher.init(Cipher.ENCRYPT_MODE, chavePublicaDestinatario);
            byte[] chaveCifrada = cipher.doFinal(chaveSimetrica.getEncoded());
            return Base64.getEncoder().encodeToString(chaveCifrada);
        } catch (Exception e) {
            throw new SecurityException("Erro ao cifrar chave simétrica com RSA Público: " + e.getMessage(), e);
        }
    }

    /**
     * Decifra a chave de sessão AES usando a Chave Privada RSA do destinatário.
     */
    public static SecretKey decifrarChaveAESComPrivadaRSA(String chaveCifradaB64, PrivateKey chavePrivadaDestinatario) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMACAO_RSA);
            cipher.init(Cipher.DECRYPT_MODE, chavePrivadaDestinatario);
            byte[] bytesDecifrados = cipher.doFinal(Base64.getDecoder().decode(chaveCifradaB64));
            return new SecretKeySpec(bytesDecifrados, 0, bytesDecifrados.length, ALGORITMO_AES);
        } catch (Exception e) {
            throw new SecurityException("Erro ao decifrar chave AES com RSA Privado: " + e.getMessage(), e);
        }
    }

    /**
     * Decifra a chave de sessão HMAC usando a Chave Privada RSA do destinatário.
     */
    public static SecretKey decifrarChaveHMACComPrivadaRSA(String chaveCifradaB64, PrivateKey chavePrivadaDestinatario) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMACAO_RSA);
            cipher.init(Cipher.DECRYPT_MODE, chavePrivadaDestinatario);
            byte[] bytesDecifrados = cipher.doFinal(Base64.getDecoder().decode(chaveCifradaB64));
            return new SecretKeySpec(bytesDecifrados, 0, bytesDecifrados.length, ALGORITMO_HMAC);
        } catch (Exception e) {
            throw new SecurityException("Erro ao decifrar chave HMAC com RSA Privado: " + e.getMessage(), e);
        }
    }

    // =========================================================================
    // INTEGRIDADE (HMAC-SHA256) E ASSINATURA DIGITAL (RSA PRIVADO -> PÚBLICO)
    // =========================================================================

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
            Cipher cipher = Cipher.getInstance(TRANSFORMACAO_RSA);
            cipher.init(Cipher.ENCRYPT_MODE, chavePrivadaEmissor);
            byte[] assinaturaBytes = cipher.doFinal(hashHmacB64.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(assinaturaBytes);
        } catch (Exception e) {
            throw new SecurityException("Erro ao assinar HMAC com chave privada RSA: " + e.getMessage(), e);
        }
    }

    public static String descriptografarHmacComChavePublicaRSA(String assinaturaRsaB64, PublicKey chavePublicaEmissor) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMACAO_RSA);
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
        // Comparação em tempo constante contra ataques de timing
        return MessageDigest.isEqual(
                hashExtraidoDaAssinatura.getBytes(StandardCharsets.UTF_8),
                hashCalculadoLocalmente.getBytes(StandardCharsets.UTF_8)
        );
    }

    // =========================================================================
    // SERIALIZAÇÃO BASE64 DE CHAVES PÚBLICAS E UTILITÁRIOS
    // =========================================================================

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
