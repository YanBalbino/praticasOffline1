package impl;

import no.NoP2P;

/**
 * Processo independente para o Nó P1 (ID=1, Porta UDP 8001, arquivos 11 a 20).
 */
public class ImplNoP1 {
    public static void main(String[] args) {
        boolean interativo = !(args.length > 0 && args[0].equalsIgnoreCase("--headless"));
        new NoP2P(1, interativo);
    }
}
