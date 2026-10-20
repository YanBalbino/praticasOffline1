package utils;

import java.security.PublicKey;
import javax.crypto.SecretKey;

// Guarda, para um cliente UDP, as chaves negociadas durante o handshake.
public class SessaoCliente {
    private final PublicKey chavePublica;
    private SecretKey chaveAES;
    private byte[] chaveHMAC;
    private boolean pronta;

    public SessaoCliente(PublicKey chavePublica) {
        this.chavePublica = chavePublica;
    }

    public PublicKey getChavePublica() {
        return chavePublica;
    }

    public SecretKey getChaveAES() {
        return chaveAES;
    }

    public byte[] getChaveHMAC() {
        return chaveHMAC;
    }

    public boolean isPronta() {
        return pronta;
    }

    // Só disponibiliza a sessão para comandos após enviar SESSION_OK ao cliente.
    public void confirmar(SecretKey chaveAES, byte[] chaveHMAC) {
        this.chaveAES = chaveAES;
        this.chaveHMAC = chaveHMAC;
        this.pronta = true;
    }
}
