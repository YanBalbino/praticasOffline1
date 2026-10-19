package seguranca;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import javax.crypto.SecretKey;

import log.Color;

/**
 * Representa o Envelope Criptográfico Híbrido trafegado salto a salto entre os nós P0..P5 no anel UDP.
 *
 * Formato serializado:
 *   ENVELOPE|nomeEmissor|msgCifradaAES|assinaturaRSA_do_HMAC|chaveAesCifradaRSA|chaveHmacCifradaRSA|chavePublicaEmissorRSA
 */
public class EnvelopeCriptografico {

    private static final File ARQUIVO_LOG = resolverArquivoLog();
    private static final DateTimeFormatter FORMATADOR_DATA = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final String nomeEmissor;
    private final String mensagemOriginal;
    private final String mensagemCifradaAES;
    private final String hashHmacValido;
    private final String assinaturaDigitalRSA;

    public EnvelopeCriptografico(
            String nomeEmissor,
            String mensagemOriginal,
            String mensagemCifradaAES,
            String hashHmacValido,
            String assinaturaDigitalRSA) {
        this.nomeEmissor = nomeEmissor;
        this.mensagemOriginal = mensagemOriginal;
        this.mensagemCifradaAES = mensagemCifradaAES;
        this.hashHmacValido = hashHmacValido;
        this.assinaturaDigitalRSA = assinaturaDigitalRSA;
    }

    private static File resolverArquivoLog() {
        File dirQuestao3 = new File("questao3");
        if (dirQuestao3.exists() && dirQuestao3.isDirectory()) {
            return new File(dirQuestao3, "logs_canal_seguro.txt");
        }
        File dirPraticasQuestao3 = new File("praticasOffline1/questao3");
        if (dirPraticasQuestao3.exists() && dirPraticasQuestao3.isDirectory()) {
            return new File(dirPraticasQuestao3, "logs_canal_seguro.txt");
        }
        return new File("logs_canal_seguro.txt");
    }

    public String getNomeEmissor() {
        return nomeEmissor;
    }

    public String getMensagemOriginal() {
        return mensagemOriginal;
    }

    public String getMensagemCifradaAES() {
        return mensagemCifradaAES;
    }

    public String getHashHmacValido() {
        return hashHmacValido;
    }

    public String getAssinaturaDigitalRSA() {
        return assinaturaDigitalRSA;
    }

    /**
     * Empacota uma mensagem com AES, HMAC-SHA256 e encapsulamento RSA das chaves de sessão para o próximo salto.
     */
    public static String criarEnvelope(
            String mensagemPlano,
            SecretKey chaveAES,
            SecretKey chaveHMAC,
            KeyPair parChavesRSAEmissor,
            PublicKey chavePublicaDestinatario,
            String nomeEmissor,
            String nomeDestinatario) {

        String msgCifradaB64 = CriptoUtils.cifrarAES(mensagemPlano, chaveAES);
        String hashHmacB64 = CriptoUtils.calcularHMAC(msgCifradaB64, chaveHMAC);
        String assinaturaRsaB64 = CriptoUtils.criptografarHmacComChavePrivadaRSA(
                hashHmacB64,
                parChavesRSAEmissor.getPrivate()
        );

        String chaveAesCifradaRsaB64 = CriptoUtils.cifrarChaveSimetricaComPublicaRSA(chaveAES, chavePublicaDestinatario);
        String chaveHmacCifradaRsaB64 = CriptoUtils.cifrarChaveSimetricaComPublicaRSA(chaveHMAC, chavePublicaDestinatario);
        String chavePublicaEmissorB64 = CriptoUtils.chavePublicaParaBase64(parChavesRSAEmissor.getPublic());

        registrarLog("SEGURANCA", "[" + nomeEmissor + " -> " + nomeDestinatario + " | ENCRIPTAÇÃO AES/HMAC] "
                + "AES_Cipher=" + CriptoUtils.resumirBase64(msgCifradaB64)
                + " | HMAC=" + CriptoUtils.resumirBase64(hashHmacB64)
                + " | ChaveAES_RSA=" + CriptoUtils.resumirBase64(chaveAesCifradaRsaB64));

        return "ENVELOPE|" + nomeEmissor + "|" + msgCifradaB64 + "|" + assinaturaRsaB64 + "|"
                + chaveAesCifradaRsaB64 + "|" + chaveHmacCifradaRsaB64 + "|" + chavePublicaEmissorB64;
    }

    /**
     * Simula um pacote adulterado no canal ou com HMAC inválido (Caso 3: P4 enviando para P5).
     */
    public static String criarEnvelopeComFalhaIntegridade(
            String mensagemPlano,
            SecretKey chaveAES,
            SecretKey chaveHMAC,
            KeyPair parChavesRSAEmissor,
            PublicKey chavePublicaDestinatario,
            String nomeEmissor,
            String nomeDestinatario) {

        String msgCifradaB64 = CriptoUtils.cifrarAES(mensagemPlano, chaveAES);

        // Gera um HMAC inválido/adulterado que não corresponde ao texto cifrado trafegado
        String hashHmacAdulterado = CriptoUtils.calcularHMAC(msgCifradaB64 + "_PACOTE_ADULTERADO_NO_CANAL", chaveHMAC);
        String assinaturaRsaCorrompida = CriptoUtils.criptografarHmacComChavePrivadaRSA(
                hashHmacAdulterado,
                parChavesRSAEmissor.getPrivate()
        );

        String chaveAesCifradaRsaB64 = CriptoUtils.cifrarChaveSimetricaComPublicaRSA(chaveAES, chavePublicaDestinatario);
        String chaveHmacCifradaRsaB64 = CriptoUtils.cifrarChaveSimetricaComPublicaRSA(chaveHMAC, chavePublicaDestinatario);
        String chavePublicaEmissorB64 = CriptoUtils.chavePublicaParaBase64(parChavesRSAEmissor.getPublic());

        registrarLog("ALERTA", "[" + nomeEmissor + " -> " + nomeDestinatario + " | SIMULAÇÃO DE ADULTERAÇÃO NO CANAL] "
                + "Enviando pacote cifrado com HMAC adulterado (" + CriptoUtils.resumirBase64(hashHmacAdulterado) + ")");

        return "ENVELOPE|" + nomeEmissor + "|" + msgCifradaB64 + "|" + assinaturaRsaCorrompida + "|"
                + chaveAesCifradaRsaB64 + "|" + chaveHmacCifradaRsaB64 + "|" + chavePublicaEmissorB64;
    }

    /**
     * Abre e valida o Envelope Criptográfico no nó receptor do salto:
     * 1. Decifra as chaves AES e HMAC com a Chave Privada RSA do nó receptor;
     * 2. Verifica a assinatura RSA e compara o HMAC recebido com o HMAC calculado localmente;
     * 3. Se houver divergência (Caso 3), registra a falha no log e lança SecurityException;
     * 4. Se válido, decifra o payload AES e retorna o EnvelopeCriptografico.
     */
    public static EnvelopeCriptografico abrirEValidarEnvelope(
            String pacoteRecebido,
            String nomeDestinatario,
            PrivateKey chavePrivadaDestinatario) {

        if (pacoteRecebido == null || !pacoteRecebido.startsWith("ENVELOPE|")) {
            throw new SecurityException("Pacote recebido fora do formato de Envelope Criptográfico.");
        }

        String[] partes = pacoteRecebido.split("\\|");
        if (partes.length != 7) {
            throw new SecurityException("Envelope Criptográfico malformado (esperados 7 campos, recebidos " + partes.length + ").");
        }

        String nomeEmissor = partes[1].trim();
        String msgCifradaB64 = partes[2].trim();
        String assinaturaRsaB64 = partes[3].trim();
        String chaveAesCifradaRsaB64 = partes[4].trim();
        String chaveHmacCifradaRsaB64 = partes[5].trim();
        String chavePublicaEmissorB64 = partes[6].trim();

        SecretKey chaveAES = CriptoUtils.decifrarChaveAESComPrivadaRSA(chaveAesCifradaRsaB64, chavePrivadaDestinatario);
        SecretKey chaveHMAC = CriptoUtils.decifrarChaveHMACComPrivadaRSA(chaveHmacCifradaRsaB64, chavePrivadaDestinatario);
        PublicKey chavePublicaEmissor = CriptoUtils.chavePublicaDeBase64(chavePublicaEmissorB64);

        String hashExtraidoDaAssinatura = CriptoUtils.descriptografarHmacComChavePublicaRSA(
                assinaturaRsaB64,
                chavePublicaEmissor
        );
        String hashCalculadoLocalmente = CriptoUtils.calcularHMAC(msgCifradaB64, chaveHMAC);

        if (!CriptoUtils.validarHashes(hashExtraidoDaAssinatura, hashCalculadoLocalmente)) {
            String msgErro = "[" + nomeDestinatario + " <- FALHA DE INTEGRIDADE/AUTENTICIDADE de " + nomeEmissor + "] "
                    + "Divergência de HMAC detectada! HMAC recebido (" + CriptoUtils.resumirBase64(hashExtraidoDaAssinatura)
                    + ") != HMAC calculado (" + CriptoUtils.resumirBase64(hashCalculadoLocalmente)
                    + "). Pacote descartado e repasse interrompido!";
            registrarLog("ERRO", msgErro);
            throw new SecurityException(msgErro);
        }

        String mensagemOriginal = CriptoUtils.decifrarAES(msgCifradaB64, chaveAES);

        registrarLog("SEGURANCA", "[" + nomeDestinatario + " <- " + nomeEmissor + " | VALIDAÇÃO CRIPTOGRÁFICA OK] "
                + "Chaves AES/HMAC decifradas via RSA | Integridade HMAC verificada ("
                + CriptoUtils.resumirBase64(hashCalculadoLocalmente) + ") | Payload AES decifrado com sucesso");

        return new EnvelopeCriptografico(
                nomeEmissor,
                mensagemOriginal,
                msgCifradaB64,
                hashCalculadoLocalmente,
                assinaturaRsaB64
        );
    }

    public static synchronized void registrarLog(String nivel, String mensagem) {
        String timestamp = LocalDateTime.now().format(FORMATADOR_DATA);
        String linhaArquivo = "[" + timestamp + "] [" + nivel + "] " + mensagem + System.lineSeparator();

        switch (nivel.toUpperCase()) {
            case "ERRO":
                Color.erro(mensagem);
                break;
            case "SUCESSO":
                Color.sucesso(mensagem);
                break;
            case "INFO":
                Color.info(mensagem);
                break;
            case "ALERTA":
                Color.alerta(mensagem);
                break;
            default:
                Color.seguranca(mensagem);
                break;
        }

        try (FileOutputStream fos = new FileOutputStream(ARQUIVO_LOG, true)) {
            fos.write(linhaArquivo.getBytes(StandardCharsets.UTF_8));
            fos.flush();
            fos.getFD().sync();
        } catch (IOException e) {
            Color.erro("Falha ao gravar em " + ARQUIVO_LOG.getAbsolutePath() + ": " + e.getMessage());
        }
    }
}
