package utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class ImplRSA {

    private PublicKey chavePublica;
    private PrivateKey chavePrivada;

    // Padding seguro (OAEP) em vez de
    // RSA puro sem padding
    private static final String PADDING =
            "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    public ImplRSA() throws NoSuchAlgorithmException {
        gerarChaves();
    }

    private void gerarChaves() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("RSA");
        SecureRandom sr =
                new SecureRandom();

        // Inicializa com 2048 bits
        // (padrão mínimo recomendado atualmente)
        kpg.initialize(2048, sr);
        KeyPair kp = kpg.generateKeyPair();

        chavePublica = kp.getPublic();
        String chavePublicaBase64 =
                Base64.getEncoder().encodeToString(chavePublica.getEncoded());
        System.out.println("Chave pública (Base64):\n" +
                chavePublicaBase64 + "\n");

        chavePrivada = kp.getPrivate();
        String chavePrivadaBase64 =
                Base64.getEncoder().encodeToString(chavePrivada.getEncoded());
        System.out.println("Chave privada (Base64):\n" +
                chavePrivadaBase64 + "\n");
    }

    public String cifrar(String msg) throws NoSuchAlgorithmException,
            NoSuchPaddingException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException {

        Cipher cifrador = Cipher.getInstance(PADDING);
        cifrador.init(Cipher.ENCRYPT_MODE, chavePublica);

        // Garante o uso de UTF-8 para evitar problemas de Charset
        byte[] bytesMsgCifrada =
                cifrador.doFinal(msg.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(bytesMsgCifrada);
    }

    public String decifrar(String msgCifradaBase64) throws NoSuchAlgorithmException,
            NoSuchPaddingException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException {

        byte[] bytesMsgCifrada =
                Base64.getDecoder().decode(msgCifradaBase64);

        Cipher decifrador = Cipher.getInstance(PADDING);
        decifrador.init(Cipher.DECRYPT_MODE, chavePrivada);

        byte[] bytesMsgDecifrada =
                decifrador.doFinal(bytesMsgCifrada);

        return new String(bytesMsgDecifrada, StandardCharsets.UTF_8);
    }
}
