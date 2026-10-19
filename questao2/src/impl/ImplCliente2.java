package impl;

import cliente.Cliente;
import diretorio.ServidorDiretorio;

/**
 * Processo independente para o Cliente 2.
 */
public class ImplCliente2 {
    public static void main(String[] args) {
        new Cliente("Cliente 2", "localhost", ServidorDiretorio.PORTA_DIRETORIO, true);
    }
}
