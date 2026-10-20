package utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class ImplRSA {

    // mantidas para entidade poder guardar suas chaves pós geração
    private PublicKey chavePublica;
    private PrivateKey chavePrivada;

    // Padding seguro (OAEP) em vez de
    // RSA puro sem padding
    private static final String PADDING = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    public ImplRSA() throws NoSuchAlgorithmException {
        gerarChaves();
    }

    public PublicKey getChavePublica() {
        return chavePublica;
    }

    private void gerarChaves() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        SecureRandom sr = new SecureRandom();

        // Inicializa com 2048 bits
        // (padrão mínimo recomendado atualmente)
        kpg.initialize(2048, sr);
        KeyPair kp = kpg.generateKeyPair();

        chavePublica = kp.getPublic();
        chavePrivada = kp.getPrivate();
    }

    public byte[] cifrar(byte[] msg, PublicKey chavePublica) throws NoSuchAlgorithmException,
            NoSuchPaddingException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException {

        Cipher cifrador = Cipher.getInstance(PADDING);
        cifrador.init(Cipher.ENCRYPT_MODE, chavePublica);

        byte[] bytesMsgCifrada = cifrador.doFinal(msg);

        return bytesMsgCifrada;
    }

    public byte[] decifrar(byte[] msgCifrada) throws NoSuchAlgorithmException,
            NoSuchPaddingException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException {

        Cipher decifrador = Cipher.getInstance(PADDING);
        decifrador.init(Cipher.DECRYPT_MODE, chavePrivada);

        byte[] bytesMsgDecifrada = decifrador.doFinal(msgCifrada);

        return bytesMsgDecifrada;
    }

    // Assina os bytes do HMAC com a chave privada desta entidade
    // Signature calcula SHA-256 internamente
    public byte[] assinar(byte[] mac) throws GeneralSecurityException {
        Signature assinatura = Signature.getInstance("SHA256withRSA");
        assinatura.initSign(chavePrivada);
        assinatura.update(mac);
        return assinatura.sign();
    }

    // A chave pública precisa pertencer ao emissor da mensagem recebida.
    public boolean verificarAssinatura(byte[] mac, byte[] assinaturaRecebida, PublicKey chavePublicaEmissor)
            throws GeneralSecurityException {
        Signature verificador = Signature.getInstance("SHA256withRSA");
        verificador.initVerify(chavePublicaEmissor);
        verificador.update(mac);
        return verificador.verify(assinaturaRecebida);
    }
}
