package utils;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.SecretKey;

// DATA|base64(IV + AES cifrado)|base64(RSA privada sobre HMAC do campo DATA+cifrado)
public class EnvelopeSeguro {
    public static String proteger(String mensagem, ImplAES256 aes, SecretKey chaveAES, byte[] chaveHMAC, ImplRSA rsa) throws GeneralSecurityException {
        String conteudo = "DATA|" + Base64.getEncoder().encodeToString(aes.cifrar(mensagem, chaveAES));
        byte[] mac = ImplHMAC.gerarMAC(conteudo.getBytes(StandardCharsets.UTF_8), chaveHMAC);

        return conteudo + "|" + Base64.getEncoder().encodeToString(rsa.assinar(mac));
    }

    public static String abrir(String envelope, ImplAES256 aes, SecretKey chaveAES, byte[] chaveHMAC, ImplRSA rsa, PublicKey publicaEmissor) throws GeneralSecurityException {
        String[] partes = envelope.split("\\|", -1);
        if (partes.length != 3 || !"DATA".equals(partes[0])) {
            throw new SecurityException("Formato de envelope inválido.");
        }

        String conteudo = partes[0] + "|" + partes[1];
        byte[] macEsperado = ImplHMAC.gerarMAC(conteudo.getBytes(StandardCharsets.UTF_8), chaveHMAC);
        try {
            byte[] assinatura = Base64.getDecoder().decode(partes[2]);
            if (!rsa.verificarAssinatura(macEsperado, assinatura, publicaEmissor)) {
                throw new SecurityException("HMAC/assinatura inválido.");
            }
            byte[] cifrado = Base64.getDecoder().decode(partes[1]);
            
            return new String(aes.decifrar(cifrado, chaveAES), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new SecurityException("Envelope inválido.", e);
        }
    }
}
