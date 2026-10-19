package impl;

import diretorio.ServidorDiretorio;
import servidor.ServidorCalculadora;

/**
 * Processo independente para o Servidor de Calculadora S2 (192.168.0.102:7002).
 */
public class ImplServidorS2 {
    public static void main(String[] args) {
        new ServidorCalculadora("S2", "192.168.0.102", 7002, "localhost", ServidorDiretorio.PORTA_DIRETORIO, false);
    }
}
