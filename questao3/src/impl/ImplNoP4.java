package impl;

import no.NoP2P;

/**
 * Processo independente para o Nó P4 (ID=4, Porta UDP 8004, arquivos 41 a 50).
 */
public class ImplNoP4 {
    public static void main(String[] args) {
        boolean interativo = !(args.length > 0 && args[0].equalsIgnoreCase("--headless"));
        new NoP2P(4, interativo);
    }
}
