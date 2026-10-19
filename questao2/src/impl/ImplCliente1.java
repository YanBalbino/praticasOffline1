package impl;

import cliente.Cliente;
import diretorio.ServidorDiretorio;

/**
 * Processo independente para o Cliente 1.
 */
public class ImplCliente1 {
    public static void main(String[] args) {
        new Cliente("Cliente 1", "localhost", ServidorDiretorio.PORTA_DIRETORIO, true);
    }
}
