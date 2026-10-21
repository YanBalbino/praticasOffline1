package utils;

import java.security.PublicKey;
import javax.crypto.SecretKey;

// Chaves da sessão negociadas com um par remoto; antes de SESSION, só sua pública é conhecida.
public class SessaoSegura {
    private final PublicKey publicaRemota;
    private SecretKey chaveAES;
    private byte[] chaveHMAC;

    public SessaoSegura(PublicKey publicaRemota) {
        this.publicaRemota = publicaRemota;
    }

    public void confirmar(SecretKey chaveAES, byte[] chaveHMAC) {
        this.chaveAES = chaveAES;
        this.chaveHMAC = chaveHMAC;
    }

    public boolean pronta() {
        return chaveAES != null;
    }

    public PublicKey getPublicaRemota() { return publicaRemota; }
    public SecretKey getChaveAES() { return chaveAES; }
    public byte[] getChaveHMAC() { return chaveHMAC; }
}
