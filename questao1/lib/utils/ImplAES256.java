package utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

public class ImplAES256 {

    public byte[] cifrar(String textoAberto, SecretKey chave) {

        try {

            // AES possui bloco de 128 bits = 16 bytes para vetor de inicialização
            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            IvParameterSpec parametros = new IvParameterSpec(iv);

            Cipher cifrador = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cifrador.init(Cipher.ENCRYPT_MODE, chave, parametros);

            byte[] dadosCifrados = cifrador.doFinal(textoAberto.getBytes(StandardCharsets.UTF_8));

            /*
             * Armazena IV + texto cifrado.
             * O IV não precisa ser secreto.
             */
            byte[] resultado = new byte[iv.length + dadosCifrados.length];

            System.arraycopy(iv, 0, resultado, 0, iv.length);
            System.arraycopy(dadosCifrados, 0, resultado, iv.length, dadosCifrados.length);

            return resultado;

        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Erro ao cifrar.", e);
        }
    }

    public byte[] decifrar(String textoCifrado, SecretKey chave) {

        try {

            byte[] dados = Base64.getDecoder().decode(textoCifrado);
            
            // se tamanho do texto não for múltiplo de 16 bytes + 16 bytes do IV, descarta
            if (dados.length < 32 || (dados.length - 16) % 16 != 0) {
                throw new IllegalArgumentException(
                        "Tamanho inválido para texto cifrado.");
            }

            /*
             * Os primeiros 16 bytes são o IV.
             */
            byte[] iv = new byte[16];
            System.arraycopy(dados, 0, iv, 0, iv.length);
            IvParameterSpec parametros = new IvParameterSpec(iv);

            /*
             * O restante é o texto cifrado.
             */
            byte[] dadosCifrados = new byte[dados.length - iv.length];
            System.arraycopy(dados, iv.length, dadosCifrados, 0, dadosCifrados.length);

            Cipher decriptador = Cipher.getInstance("AES/CBC/PKCS5Padding");

            decriptador.init(Cipher.DECRYPT_MODE, chave, parametros);

            byte[] dadosDecifrados = decriptador.doFinal(dadosCifrados);

            return dadosDecifrados;

        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Erro ao decifrar.", e);
        }
    }

}


