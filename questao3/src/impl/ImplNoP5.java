package impl;

import no.NoP2P;

/**
 * Processo independente para o Nó P5 (ID=5, Porta UDP 8005, arquivos 51 a 60).
 */
public class ImplNoP5 {
    public static void main(String[] args) {
        boolean interativo = !(args.length > 0 && args[0].equalsIgnoreCase("--headless"));
        new NoP2P(5, interativo);
    }
}
