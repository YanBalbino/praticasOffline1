package impl;

import no.NoP2P;

/**
 * Processo independente para o Nó P2 (ID=2, Porta UDP 8002, arquivos 21 a 30).
 */
public class ImplNoP2 {
    public static void main(String[] args) {
        boolean interativo = !(args.length > 0 && args[0].equalsIgnoreCase("--headless"));
        new NoP2P(2, interativo);
    }
}
