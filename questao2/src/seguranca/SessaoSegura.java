package seguranca;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

/**
 * Representa uma Sessão Criptográfica Híbrida estabelecida via Handshake RSA entre dois processos
 * (Cliente <-> Diretório, ServidorCalc <-> Diretório, ou Cliente <-> ServidorCalc).
 *
 * Fluxo do Handshake RSA (inspirado no HandshakeHandler e TLS):
 * 1. Servidor envia sua identidade e sua Chave Pública RSA:
 *    HANDSHAKE_SERVER_HELLO|nomeServidor|chavePublicaServidorB64
 * 2. Cliente gera as chaves simétricas exclusivas da sessão (AES + HMAC), cifra ambas com a
 *    Chave Pública RSA do Servidor e envia junto com sua própria Chave Pública RSA:
 *    HANDSHAKE_CLIENT_KEYS|nomeCliente|chaveAesCifradaRSA|chaveHmacCifradaRSA|chavePublicaClienteB64
 * 3. Servidor decifra as chaves AES e HMAC usando sua Chave Privada RSA.
 * 4. Ambos passam a compartilhar as mesmas chaves simétricas de sessão (AES + HMAC) e conhecem
 *    a Chave Pública RSA um do outro para validar assinaturas digitais em ambas as direções.
 */
public class SessaoSegura {

    private final String nomeLocal;
    private final String nomeRemoto;
    private final KeyPair parChavesRSALocal;
    private final PublicKey chavePublicaRSARemota;
    private final SecretKey chaveSessaoAES;
    private final SecretKey chaveSessaoHMAC;

    public SessaoSegura(
            String nomeLocal,
            String nomeRemoto,
            KeyPair parChavesRSALocal,
            PublicKey chavePublicaRSARemota,
            SecretKey chaveSessaoAES,
            SecretKey chaveSessaoHMAC) {
        this.nomeLocal = nomeLocal;
        this.nomeRemoto = nomeRemoto;
        this.parChavesRSALocal = parChavesRSALocal;
        this.chavePublicaRSARemota = chavePublicaRSARemota;
        this.chaveSessaoAES = chaveSessaoAES;
        this.chaveSessaoHMAC = chaveSessaoHMAC;
    }

    /**
     * Executa o Handshake atuando como Cliente (iniciador da conexão).
     * Recebe a Chave Pública RSA do Servidor, gera chaves efêmeras AES e HMAC para a sessão,
     * cifra ambas com a Chave Pública RSA do Servidor e envia ao Servidor.
     */
    public static SessaoSegura realizarHandshakeComoCliente(
            BufferedReader leitor,
            PrintWriter escritor,
            String nomeCliente,
            KeyPair parChavesRSACliente) throws IOException {

        String serverHello = leitor.readLine();
        if (serverHello == null || !serverHello.startsWith("HANDSHAKE_SERVER_HELLO|")) {
            throw new SecurityException("Falha no Handshake RSA: Servidor não enviou HANDSHAKE_SERVER_HELLO válido.");
        }

        String[] partesHello = serverHello.split("\\|");
        if (partesHello.length != 3) {
            throw new SecurityException("Falha no Handshake RSA: Formato HANDSHAKE_SERVER_HELLO inválido.");
        }

        String nomeServidor = partesHello[1].trim();
        String chavePubServidorB64 = partesHello[2].trim();
        PublicKey chavePublicaServidor = CriptoUtils.chavePublicaDeBase64(chavePubServidorB64);

        // Gera chaves simétricas exclusivas para esta sessão
        SecretKey chaveSessaoAES = CriptoUtils.gerarChaveAES();
        SecretKey chaveSessaoHMAC = CriptoUtils.gerarChaveHMAC();

        // Cifra as chaves simétricas da sessão com a Chave Pública RSA do Servidor
        String aesCifradaRSA = CriptoUtils.cifrarChaveSimetricaComPublicaRSA(chaveSessaoAES, chavePublicaServidor);
        String hmacCifradaRSA = CriptoUtils.cifrarChaveSimetricaComPublicaRSA(chaveSessaoHMAC, chavePublicaServidor);
        String chavePubClienteB64 = CriptoUtils.chavePublicaParaBase64(parChavesRSACliente.getPublic());

        String msgClientKeys = "HANDSHAKE_CLIENT_KEYS|" + nomeCliente + "|"
                + aesCifradaRSA + "|" + hmacCifradaRSA + "|" + chavePubClienteB64;
        escritor.println(msgClientKeys);
        escritor.flush();

        EnvelopeCriptografico.registrarLog("SEGURANCA", "[HANDSHAKE RSA: " + nomeCliente + " -> " + nomeServidor + "] "
                + "Chaves de sessão AES e HMAC geradas e cifradas com PubKey RSA de " + nomeServidor
                + " (AES_RSA=" + CriptoUtils.resumirBase64(aesCifradaRSA)
                + ", HMAC_RSA=" + CriptoUtils.resumirBase64(hmacCifradaRSA) + ")");

        return new SessaoSegura(
                nomeCliente,
                nomeServidor,
                parChavesRSACliente,
                chavePublicaServidor,
                chaveSessaoAES,
                chaveSessaoHMAC
        );
    }

    /**
     * Executa o Handshake atuando como Servidor (receptor da conexão).
     * Envia sua Chave Pública RSA ao Cliente e decifra as chaves de sessão AES e HMAC
     * usando sua Chave Privada RSA.
     */
    public static SessaoSegura realizarHandshakeComoServidor(
            BufferedReader leitor,
            PrintWriter escritor,
            String nomeServidor,
            KeyPair parChavesRSAServidor) throws IOException {

        String chavePubServidorB64 = CriptoUtils.chavePublicaParaBase64(parChavesRSAServidor.getPublic());
        escritor.println("HANDSHAKE_SERVER_HELLO|" + nomeServidor + "|" + chavePubServidorB64);
        escritor.flush();

        String clientKeysMsg = leitor.readLine();
        if (clientKeysMsg == null) {
            return null;
        }
        if (!clientKeysMsg.startsWith("HANDSHAKE_CLIENT_KEYS|")) {
            throw new SecurityException("Falha no Handshake RSA: Cliente não enviou HANDSHAKE_CLIENT_KEYS.");
        }

        String[] partes = clientKeysMsg.split("\\|");
        if (partes.length != 5) {
            throw new SecurityException("Falha no Handshake RSA: Formato HANDSHAKE_CLIENT_KEYS malformado.");
        }

        String nomeCliente = partes[1].trim();
        String aesCifradaRSA = partes[2].trim();
        String hmacCifradaRSA = partes[3].trim();
        String chavePubClienteB64 = partes[4].trim();

        PrivateKey chavePrivadaServidor = parChavesRSAServidor.getPrivate();
        SecretKey chaveSessaoAES = CriptoUtils.decifrarChaveAESComPrivadaRSA(aesCifradaRSA, chavePrivadaServidor);
        SecretKey chaveSessaoHMAC = CriptoUtils.decifrarChaveHMACComPrivadaRSA(hmacCifradaRSA, chavePrivadaServidor);
        PublicKey chavePublicaCliente = CriptoUtils.chavePublicaDeBase64(chavePubClienteB64);

        EnvelopeCriptografico.registrarLog("SEGURANCA", "[HANDSHAKE RSA: " + nomeServidor + " <- " + nomeCliente + "] "
                + "Chaves de sessão AES e HMAC decifradas com PrivKey RSA de " + nomeServidor + ". Sessão híbrida estabelecida!");

        return new SessaoSegura(
                nomeServidor,
                nomeCliente,
                parChavesRSAServidor,
                chavePublicaCliente,
                chaveSessaoAES,
                chaveSessaoHMAC
        );
    }

    public String empacotarMensagem(String mensagemPlano) {
        return EnvelopeCriptografico.criarEnvelope(
                mensagemPlano,
                chaveSessaoAES,
                chaveSessaoHMAC,
                parChavesRSALocal,
                chavePublicaRSARemota,
                nomeLocal
        );
    }

    public String empacotarMensagemComHmacCorrompido(String mensagemPlano) {
        return EnvelopeCriptografico.criarEnvelopeComHmacCorrompido(
                mensagemPlano,
                chaveSessaoAES,
                chaveSessaoHMAC,
                parChavesRSALocal,
                chavePublicaRSARemota,
                nomeLocal
        );
    }

    public EnvelopeCriptografico desempacotarEValidar(String pacoteRecebido) {
        return EnvelopeCriptografico.abrirEValidarEnvelope(
                pacoteRecebido,
                nomeLocal,
                parChavesRSALocal.getPrivate()
        );
    }

    public String getNomeLocal() {
        return nomeLocal;
    }

    public String getNomeRemoto() {
        return nomeRemoto;
    }

    public KeyPair getParChavesRSALocal() {
        return parChavesRSALocal;
    }

    public PublicKey getChavePublicaRSARemota() {
        return chavePublicaRSARemota;
    }

    public SecretKey getChaveSessaoAES() {
        return chaveSessaoAES;
    }

    public SecretKey getChaveSessaoHMAC() {
        return chaveSessaoHMAC;
    }
}
