package impl;

import cliente.Cliente;
import diretorio.ServidorDiretorio;

/**
 * Processo independente para o Cliente 3.
 */
public class ImplCliente3 {
    public static void main(String[] args) {
        new Cliente("Cliente 3", "localhost", ServidorDiretorio.PORTA_DIRETORIO, true);
    }
}
