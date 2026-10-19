package impl;

import diretorio.ServidorDiretorio;

/**
 * Processo independente para o Servidor de Diretório (porta 6000).
 */
public class ImplServidorDiretorio {
    public static void main(String[] args) {
        new ServidorDiretorio(false);
    }
}
