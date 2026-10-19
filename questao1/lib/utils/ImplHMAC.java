package utils;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.security.MessageDigest;

public class ImplHMAC {

    // Chaves secretas trocadas por RSA
    
    public static byte[] gerarMAC(byte[] pacoteCifrado, byte[] chaveMAC) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(chaveMAC, "HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(pacoteCifrado);
    }

    public static boolean verificarMAC(byte[] pacoteCifrado, byte[] chaveMAC, byte[] macRecebido) throws Exception {
        byte[] macCalculado = gerarMAC(pacoteCifrado, chaveMAC);

        // message digest pra mascarar tempo de checagem e evitar ataques de timing
        return MessageDigest.isEqual(macCalculado, macRecebido);
    }
}
