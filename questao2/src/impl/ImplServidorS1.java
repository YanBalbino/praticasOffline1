package impl;

import diretorio.ServidorDiretorio;
import servidor.ServidorCalculadora;

/**
 * Processo independente para o Servidor de Calculadora S1 (192.168.0.101:7001).
 */
public class ImplServidorS1 {
    public static void main(String[] args) {
        new ServidorCalculadora("S1", "192.168.0.101", 7001, "localhost", ServidorDiretorio.PORTA_DIRETORIO, false);
    }
}
