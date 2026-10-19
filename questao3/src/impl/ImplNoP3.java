package impl;

import no.NoP2P;

/**
 * Processo independente para o Nó P3 (ID=3, Porta UDP 8003, arquivos 31 a 40).
 */
public class ImplNoP3 {
    public static void main(String[] args) {
        boolean interativo = !(args.length > 0 && args[0].equalsIgnoreCase("--headless"));
        new NoP2P(3, interativo);
    }
}
