package impl;

import diretorio.ServidorDiretorio;
import servidor.ServidorCalculadora;

/**
 * Processo independente para o Servidor de Calculadora S3 (192.168.0.103:7003).
 */
public class ImplServidorS3 {
    public static void main(String[] args) {
        new ServidorCalculadora("S3", "192.168.0.103", 7003, "localhost", ServidorDiretorio.PORTA_DIRETORIO, false);
    }
}
