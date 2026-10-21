package impl;

import no.NoP2P;

/**
 * Processo independente para o Nó P0 (ID=0, Porta UDP 8000, arquivos 1 a 10).
 */
public class ImplNoP0 {
    public static void main(String[] args) {
        boolean interativo = !(args.length > 0 && args[0].equalsIgnoreCase("--headless"));
        new NoP2P(0, interativo);
    }
}
