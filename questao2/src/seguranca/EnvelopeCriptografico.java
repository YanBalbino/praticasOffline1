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
 * Representa o Envelope Criptográfico Híbrido trafegado entre Clientes, Diretório e Servidores de Cálculo.
 *
 * Fluxo do Emissor:
 * 1. Criptografa a mensagem com criptografia simétrica AES utilizando a chave simétrica da sessão.
 * 2. Aplica o hash HMAC (HmacSHA256) sobre a mensagem criptografada do emissor.
 * 3. Criptografa o resultado do HMAC com criptografia assimétrica RSA utilizando a CHAVE PRIVADA do emissor (Assinatura Digital).
 * 4. Criptografa as chaves simétricas (AES e HMAC) com criptografia assimétrica RSA utilizando a CHAVE PÚBLICA do destinatário.
 *
 * Fluxo do Destinatário:
 * 1. Descriptografa as chaves simétricas (AES e HMAC) com sua CHAVE PRIVADA RSA.
 * 2. Valida o hash descriptografando a assinatura com a CHAVE PÚBLICA RSA do emissor e comparando com o HMAC calculado sobre a mensagem cifrada.
 * 3. Descriptografa a mensagem com criptografia simétrica AES utilizando a chave da sessão.
 */
public class EnvelopeCriptografico {

    private static final File ARQUIVO_LOG = resolverArquivoLog();
    private static final DateTimeFormatter FORMATADOR_DATA = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final String nomeEmissor;
    private final String mensagemOriginal;
    private final String mensagemCifradaAES;
    private final String hashHmacValido;
    private final String assinaturaDigitalRSA;

    public EnvelopeCriptografico(String nomeEmissor, String mensagemOriginal, String mensagemCifradaAES,
            String hashHmacValido, String assinaturaDigitalRSA) {
        this.nomeEmissor = nomeEmissor;
        this.mensagemOriginal = mensagemOriginal;
        this.mensagemCifradaAES = mensagemCifradaAES;
        this.hashHmacValido = hashHmacValido;
        this.assinaturaDigitalRSA = assinaturaDigitalRSA;
    }

    private static File resolverArquivoLog() {
        File dirQuestao2 = new File("questao2");
        if (dirQuestao2.exists() && dirQuestao2.isDirectory()) {
            return new File(dirQuestao2, "logs_canal_seguro.txt");
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
     * Cria o Envelope Criptográfico Híbrido completo:
     * - Payload cifrado com AES (chave da sessão);
     * - HMAC calculado sobre o texto cifrado e assinado com a Chave Privada RSA do Emissor;
     * - Chaves simétricas (AES e HMAC) cifradas com a Chave Pública RSA do Destinatário (nunca em texto claro).
     */
    public static String criarEnvelope(
            String mensagemPlano,
            SecretKey chaveAES,
            SecretKey chaveHMAC,
            KeyPair parChavesRSAEmissor,
            PublicKey chavePublicaDestinatario,
            String nomeEmissor) {

        // 1. Confidencialidade do payload: cifra a mensagem com AES
        String msgCifradaB64 = CriptoUtils.cifrarAES(mensagemPlano, chaveAES);

        // 2. Integridade: aplica o hash HMAC sobre a mensagem criptografada do emissor (Encrypt-then-MAC)
        String hashHmacB64 = CriptoUtils.calcularHMAC(msgCifradaB64, chaveHMAC);

        // 3. Autenticidade e Irretratabilidade: assina o HMAC com RSA utilizando a chave privada do emissor
        String assinaturaRsaB64 = CriptoUtils.criptografarHmacComChavePrivadaRSA(
                hashHmacB64,
                parChavesRSAEmissor.getPrivate()
        );

        // 4. Confidencialidade das chaves de sessão: cifra chaveAES e chaveHMAC com a Chave Pública RSA do destinatário
        String chaveAesCifradaRsaB64 = CriptoUtils.cifrarChaveSimetricaComPublicaRSA(chaveAES, chavePublicaDestinatario);
        String chaveHmacCifradaRsaB64 = CriptoUtils.cifrarChaveSimetricaComPublicaRSA(chaveHMAC, chavePublicaDestinatario);
        String chavePublicaEmissorB64 = CriptoUtils.chavePublicaParaBase64(parChavesRSAEmissor.getPublic());

        registrarLog("INFO", "[" + nomeEmissor + " -> ENVIO SEGURO] "
                + "AES_Cipher=" + CriptoUtils.resumirBase64(msgCifradaB64)
                + " | HMAC=" + CriptoUtils.resumirBase64(hashHmacB64)
                + " | AssinaturaRSA(PrivKey)=" + CriptoUtils.resumirBase64(assinaturaRsaB64)
                + " | ChaveAES_RSA(PubKeyDest)=" + CriptoUtils.resumirBase64(chaveAesCifradaRsaB64));

        // ENVELOPE | nomeEmissor | msgCifradaAES | assinaturaRSA_do_HMAC | chaveAesCifradaRSA | chaveHmacCifradaRSA | chavePublicaEmissorRSA
        return "ENVELOPE|" + nomeEmissor + "|" + msgCifradaB64 + "|" + assinaturaRsaB64 + "|"
                + chaveAesCifradaRsaB64 + "|" + chaveHmacCifradaRsaB64 + "|" + chavePublicaEmissorB64;
    }

    public static String criarEnvelopeComHmacCorrompido(
            String mensagemPlano,
            SecretKey chaveAES,
            SecretKey chaveHMAC,
            KeyPair parChavesRSAEmissor,
            PublicKey chavePublicaDestinatario,
            String nomeEmissor) {

        String msgCifradaB64 = CriptoUtils.cifrarAES(mensagemPlano, chaveAES);

        // Adultera o HMAC antes de assinar para simular ataque/corrupção de integridade (Caso 3)
        String hashHmacAdulterado = CriptoUtils.calcularHMAC(msgCifradaB64 + "_ADULTERADO", chaveHMAC);
        String assinaturaRsaCorrompida = CriptoUtils.criptografarHmacComChavePrivadaRSA(
                hashHmacAdulterado,
                parChavesRSAEmissor.getPrivate()
        );

        String chaveAesCifradaRsaB64 = CriptoUtils.cifrarChaveSimetricaComPublicaRSA(chaveAES, chavePublicaDestinatario);
        String chaveHmacCifradaRsaB64 = CriptoUtils.cifrarChaveSimetricaComPublicaRSA(chaveHMAC, chavePublicaDestinatario);
        String chavePublicaEmissorB64 = CriptoUtils.chavePublicaParaBase64(parChavesRSAEmissor.getPublic());

        registrarLog("ALERTA", "[" + nomeEmissor + " -> ENVIO COM HMAC ADULTERADO] "
                + "AES_Cipher=" + CriptoUtils.resumirBase64(msgCifradaB64)
                + " | HMAC_CORROMPIDO=" + CriptoUtils.resumirBase64(hashHmacAdulterado));

        return "ENVELOPE|" + nomeEmissor + "|" + msgCifradaB64 + "|" + assinaturaRsaCorrompida + "|"
                + chaveAesCifradaRsaB64 + "|" + chaveHmacCifradaRsaB64 + "|" + chavePublicaEmissorB64;
    }

    /**
     * Abre e valida o Envelope Criptográfico no Destinatário:
     * 1. Decifra as chaves simétricas (AES e HMAC) usando a CHAVE PRIVADA RSA do destinatário.
     * 2. Descriptografa a assinatura RSA usando a CHAVE PÚBLICA do emissor para obter o HMAC enviado.
     * 3. Recalcula o HMAC sobre a mensagem criptografada recebida e compara ambos (Integridade + Autenticidade + Irretratabilidade).
     * 4. Descriptografa a mensagem com criptografia simétrica AES (Confidencialidade).
     */
    public static EnvelopeCriptografico abrirEValidarEnvelope(
            String pacoteRecebido,
            String nomeDestinatario,
            PrivateKey chavePrivadaDestinatario) {

        if (pacoteRecebido == null || !pacoteRecebido.startsWith("ENVELOPE|")) {
            throw new SecurityException("Pacote fora do formato de Envelope Criptográfico!");
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

        // 1. Decifra as chaves simétricas da sessão usando a Chave Privada RSA do Destinatário
        SecretKey chaveAES = CriptoUtils.decifrarChaveAESComPrivadaRSA(chaveAesCifradaRsaB64, chavePrivadaDestinatario);
        SecretKey chaveHMAC = CriptoUtils.decifrarChaveHMACComPrivadaRSA(chaveHmacCifradaRsaB64, chavePrivadaDestinatario);
        PublicKey chavePublicaEmissor = CriptoUtils.chavePublicaDeBase64(chavePublicaEmissorB64);

        // 2. Valida autenticidade e irretratabilidade: decifra o hash HMAC usando a Chave Pública RSA do Emissor
        String hashExtraidoDaAssinatura = CriptoUtils.descriptografarHmacComChavePublicaRSA(
                assinaturaRsaB64,
                chavePublicaEmissor
        );

        // 3. Valida integridade: calcula localmente o HMAC sobre a mensagem criptografada recebida
        String hashCalculadoLocalmente = CriptoUtils.calcularHMAC(msgCifradaB64, chaveHMAC);

        if (!CriptoUtils.validarHashes(hashExtraidoDaAssinatura, hashCalculadoLocalmente)) {
            String msgErro = "[" + nomeDestinatario + " <- FALHA DE INTEGRIDADE/AUTENTICIDADE de " + nomeEmissor + "] "
                    + "HMAC extraído da assinatura RSA (" + CriptoUtils.resumirBase64(hashExtraidoDaAssinatura) + ") "
                    + "difere do HMAC calculado (" + CriptoUtils.resumirBase64(hashCalculadoLocalmente) + "). Execução rejeitada!";
            registrarLog("ERRO", msgErro);
            throw new SecurityException(msgErro);
        }

        // 4. Confidencialidade: descriptografa a mensagem com criptografia simétrica AES
        String mensagemOriginal = CriptoUtils.decifrarAES(msgCifradaB64, chaveAES);

        registrarLog("SUCESSO", "[" + nomeDestinatario + " <- CANAL SEGURO VALIDADO de " + nomeEmissor + "] "
                + "Chaves Sessão RSA(PrivKey) OK | Assinatura RSA(PubKey) OK | HMAC OK ("
                + CriptoUtils.resumirBase64(hashCalculadoLocalmente) + ") | AES Decifrado OK");

        return new EnvelopeCriptografico(
                nomeEmissor,
                mensagemOriginal,
                msgCifradaB64,
                hashCalculadoLocalmente,
                assinaturaRsaB64
        );
    }

    public static synchronized void registrarLog(String mensagem) {
        registrarLog("SEGURANCA", mensagem);
    }

    /**
     * Exibe o log colorido no terminal via Color e grava imediatamente em disco (flush + sync)
     * no arquivo logs_canal_seguro.txt enquanto o programa está em execução.
     */
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
