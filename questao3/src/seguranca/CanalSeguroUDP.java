package seguranca;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;

import javax.crypto.SecretKey;

/**
 * Gerencia o estabelecimento do Canal Seguro Salto a Salto sobre UDP entre dois nós do anel
 * (ex.: P0–P1, P1–P2, P2–P3, P3–P0, P4–P5).
 *
 * Fluxo em cada salto:
 * 1. O nó emissor solicita a Chave Pública RSA do nó destino via datagrama HANDSHAKE_REQ;
 * 2. O nó destino responde com HANDSHAKE_RESP contendo sua Chave Pública RSA (Base64);
 * 3. O nó emissor gera chaves simétricas efêmeras (AES + HMAC) exclusivas para este salto,
 *    encapsula ambas com a Chave Pública RSA do nó destino e cifra a mensagem com AES + HMAC.
 */
public class CanalSeguroUDP {

    public static final String PREFIXO_HANDSHAKE_REQ = "HANDSHAKE_REQ|";
    public static final String PREFIXO_HANDSHAKE_RESP = "HANDSHAKE_RESP|";
    private static final int TIMEOUT_HANDSHAKE_MS = 3000;

    public static class ResultadoEnvioSeguro {
        private final String envelopeSerializado;
        private final String resumoHandshake;

        public ResultadoEnvioSeguro(String envelopeSerializado, String resumoHandshake) {
            this.envelopeSerializado = envelopeSerializado;
            this.resumoHandshake = resumoHandshake;
        }

        public String getEnvelopeSerializado() {
            return envelopeSerializado;
        }

        public String getResumoHandshake() {
            return resumoHandshake;
        }
    }

    /**
     * Realiza o Handshake RSA com o próximo nó do enlace UDP e constrói o Envelope Criptográfico
     * (normal ou adulterado para o Caso 3).
     */
    public static ResultadoEnvioSeguro estabelecerCanalEPrepararEnvelope(
            String nomeEmissor,
            KeyPair parChavesRSAEmissor,
            String hostDestino,
            int portaDestino,
            String nomeDestino,
            String mensagemPlana,
            boolean simularFalhaIntegridade) throws IOException {

        PublicKey chavePublicaDestino = realizarHandshakeRSA(
                nomeEmissor,
                parChavesRSAEmissor.getPublic(),
                hostDestino,
                portaDestino,
                nomeDestino
        );

        SecretKey chaveSessaoAES = CriptoUtils.gerarChaveAES();
        SecretKey chaveSessaoHMAC = CriptoUtils.gerarChaveHMAC();

        String aesCifradaPreview = CriptoUtils.resumirBase64(
                CriptoUtils.cifrarChaveSimetricaComPublicaRSA(chaveSessaoAES, chavePublicaDestino)
        );

        String resumoHandshake = "Canal seguro estabelecido no enlace " + nomeEmissor + "–" + nomeDestino
                + " (Troca de chaves AES/HMAC via RSA concluída | ChaveAES_RSA=" + aesCifradaPreview + ")";
        EnvelopeCriptografico.registrarLog("SEGURANCA", "[" + nomeEmissor + " <-> " + nomeDestino + "] " + resumoHandshake);

        String envelope;
        if (simularFalhaIntegridade) {
            envelope = EnvelopeCriptografico.criarEnvelopeComFalhaIntegridade(
                    mensagemPlana,
                    chaveSessaoAES,
                    chaveSessaoHMAC,
                    parChavesRSAEmissor,
                    chavePublicaDestino,
                    nomeEmissor,
                    nomeDestino
            );
        } else {
            envelope = EnvelopeCriptografico.criarEnvelope(
                    mensagemPlana,
                    chaveSessaoAES,
                    chaveSessaoHMAC,
                    parChavesRSAEmissor,
                    chavePublicaDestino,
                    nomeEmissor,
                    nomeDestino
            );
        }

        return new ResultadoEnvioSeguro(envelope, resumoHandshake);
    }

    private static PublicKey realizarHandshakeRSA(
            String nomeEmissor,
            PublicKey chavePublicaEmissor,
            String hostDestino,
            int portaDestino,
            String nomeDestino) throws IOException {

        try (DatagramSocket socketHandshake = new DatagramSocket()) {
            socketHandshake.setSoTimeout(TIMEOUT_HANDSHAKE_MS);

            String pubKeyEmissorB64 = CriptoUtils.chavePublicaParaBase64(chavePublicaEmissor);
            String req = PREFIXO_HANDSHAKE_REQ + nomeEmissor + "|" + pubKeyEmissorB64;
            byte[] bytesReq = req.getBytes(StandardCharsets.UTF_8);

            InetAddress endereco = InetAddress.getByName(hostDestino);
            DatagramPacket pctReq = new DatagramPacket(bytesReq, bytesReq.length, endereco, portaDestino);
            socketHandshake.send(pctReq);

            byte[] bufferResp = new byte[4096];
            DatagramPacket pctResp = new DatagramPacket(bufferResp, bufferResp.length);
            socketHandshake.receive(pctResp);

            String resp = new String(pctResp.getData(), 0, pctResp.getLength(), StandardCharsets.UTF_8).trim();
            if (!resp.startsWith(PREFIXO_HANDSHAKE_RESP)) {
                throw new SecurityException("Resposta inválida no Handshake RSA com " + nomeDestino + ": " + resp);
            }

            String[] partes = resp.split("\\|");
            if (partes.length < 3) {
                throw new SecurityException("Formato malformado em HANDSHAKE_RESP de " + nomeDestino);
            }

            return CriptoUtils.chavePublicaDeBase64(partes[2].trim());
        }
    }
}
