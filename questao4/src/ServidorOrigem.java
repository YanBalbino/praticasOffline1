import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Scanner;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import utils.EnvelopeSeguro;
import utils.ImplAES256;
import utils.ImplHMAC;
import utils.ImplRSA;
import utils.LogSistema;
import utils.SessaoSegura;

public class ServidorOrigem {
    private static final LogSistema LOG = LogSistema.noProjeto("questao4");
    private final int PORTA_ORIGEM = 8000;
    private final int PORTA_INVALIDACAO_BORDA = 8103;
    private HashMap<String,String> arquivos; // hashmap para agilizar buscas, não usei Set por falta de familiaridade
    private final ImplAES256 aes = new ImplAES256();
    private ImplRSA rsa;

    public ServidorOrigem(){
        arquivos = new HashMap<>();

        for (int i = 1; i <= 1000; i++){
            arquivos.put(i + "", "arquivo" + i + ".ext"); // par chave valor {id, arquivo[id].ext}
        }

        rodar();
    }

    private void rodar(){
        ServerSocket servidorOrigem = null;
        try {
            rsa = new ImplRSA();
            servidorOrigem = new ServerSocket(PORTA_ORIGEM);

            System.out.println("Servidor de origem rodando na porta " + PORTA_ORIGEM + "...");

            new Thread(new Runnable() {
                @Override
                public void run() {
                    Scanner teclado = new Scanner(System.in);
                    while (true) {
                        System.out.println("1 - Invalidar arquivo na borda | 0 - Sair do menu");
                        if (!teclado.hasNextLine()) return;
                        String opcao = teclado.nextLine().trim();
                        if ("0".equals(opcao)) return;
                        if (!"1".equals(opcao)) {
                            System.out.println("Opção inválida.");
                            continue;
                        }

                        System.out.println("Nome do arquivo:");
                        if (!teclado.hasNextLine()) return;
                        String nomeArquivo = teclado.nextLine().trim();
                        if (!nomeArquivo.matches("arquivo(?:[1-9]\\d{0,2}|1000)\\.ext")) {
                            System.out.println("[ERROR] Nome de arquivo inválido");
                            continue;
                        }
                        invalidarCache(nomeArquivo);
                    }
                }
            }).start();

            // busca novas conexões
            while (true){
                Socket servidorBorda = servidorOrigem.accept();

                try {
                    System.out.println("Servidor de borda conectado: " + servidorBorda.getInetAddress().getHostAddress());

                    // como borda só manda uma solicitação por vez, não precisa de thread
                    InputStream entrada = servidorBorda.getInputStream();
                    OutputStream saida = servidorBorda.getOutputStream();
                    SessaoSegura sessao = aceitarSessao(entrada, saida);

                    byte[] buffer = new byte[4096];
                    int bytesLidos = entrada.read(buffer);
                    if (bytesLidos == -1) {
                        System.out.println("Servidor de borda desconectado.");
                        continue;
                    }

                    String envelope = new String(buffer, 0, bytesLidos, StandardCharsets.UTF_8);
                    LOG.registrar("Borda", "Origem", "TCP RECEBIDO GET", envelope);
                    // Validar antes de decifrar e consultar arquivos; falha fecha conexão
                    String comando = EnvelopeSeguro.abrir(envelope, aes, sessao.getChaveAES(),
                            sessao.getChaveHMAC(), rsa, sessao.getPublicaRemota());
                    System.out.println("HMAC da Borda validado: " + comando);
                    LOG.registrar("Borda", "Origem", "HMAC OK GET", comando);

                    String resposta;
                    if (!comando.startsWith("GET /")) {
                        resposta = "[ERROR] Mensagem inválida";
                    } else {
                        String nomeArquivo = comando.substring(5);
                        if (!nomeArquivo.matches("arquivo(?:[1-9]\\d{0,2}|1000)\\.ext")) {
                            resposta = "[ERROR] Arquivo inválido";
                        } else {
                            String idArquivo = nomeArquivo.substring(7, nomeArquivo.length() - 4);
                            String arquivo = arquivos.get(idArquivo);
                            if (arquivo == null) {
                                resposta = "[ERROR] Arquivo não encontrado";
                            } else {
                                resposta = "DATA /" + arquivo;
                            }
                        }
                    }

                    String protegido = EnvelopeSeguro.proteger(resposta, aes, sessao.getChaveAES(),
                            sessao.getChaveHMAC(), rsa);
                    saida.write(protegido.getBytes(StandardCharsets.UTF_8));
                    LOG.registrar("Origem", "Borda", "TCP ENVIO RESPOSTA", protegido);
                    System.out.println("Resposta segura enviada: " + resposta);
                } catch (IOException | GeneralSecurityException | RuntimeException e){
                    LOG.registrar("Borda", "Origem", "FALHA CONEXAO", e.getMessage());
                    System.out.println("Erro na conexão com o servidor de borda: " + e.getMessage());
                } finally {
                    // fecha a conexão com o cliente
                    try {
                        servidorBorda.close();
                    } catch (IOException e){
                        System.out.println("Erro ao fechar conexão com o servidor de borda: " + e.getMessage());
                    }
                }
            }

        } catch (IOException | GeneralSecurityException e){
            System.out.println("Erro na conexão: " + e.getMessage());
        } finally {
            // fecha o servidor
            if (servidorOrigem != null){
                try {
                    servidorOrigem.close();
                } catch (IOException e){
                    System.out.println("Erro ao fechar o servidor: " + e.getMessage());
                }
            }
        }
    }

    // Borda inicia a conexão de GET; Origem recebe suas chaves de sessão via RSA.
    private SessaoSegura aceitarSessao(InputStream entrada, OutputStream saida)
            throws IOException, GeneralSecurityException {
        byte[] buffer = new byte[4096];
        int bytesLidos = entrada.read(buffer);
        String hello = bytesLidos == -1 ? "" : new String(buffer, 0, bytesLidos, StandardCharsets.UTF_8);
        LOG.registrar("Borda", "Origem", "TCP RECEBIDO HELLO", hello);
        String[] partes = hello.split("\\|", -1);
        if (partes.length != 2 || !"HELLO".equals(partes[0])) {
            throw new IOException("HELLO inválido.");
        }

        byte[] publicaBordaBytes = Base64.getDecoder().decode(partes[1]);
        PublicKey publicaBorda = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(publicaBordaBytes));
        SessaoSegura sessao = new SessaoSegura(publicaBorda);
        String publicaOrigemBase64 = Base64.getEncoder().encodeToString(rsa.getChavePublica().getEncoded());
        String resposta = "PUBLIC_KEY|" + publicaOrigemBase64;
        saida.write(resposta.getBytes(StandardCharsets.UTF_8));
        LOG.registrar("Origem", "Borda", "TCP ENVIO PUBLIC_KEY", resposta);

        buffer = new byte[4096];
        bytesLidos = entrada.read(buffer);
        String session = bytesLidos == -1 ? "" : new String(buffer, 0, bytesLidos, StandardCharsets.UTF_8);
        LOG.registrar("Borda", "Origem", "TCP RECEBIDO SESSION", session);
        partes = session.split("\\|", -1);
        if (partes.length != 3 || !"SESSION".equals(partes[0])) {
            throw new IOException("SESSION inválida.");
        }
        byte[] bytesAES = rsa.decifrar(Base64.getDecoder().decode(partes[1]));
        byte[] bytesHMAC = rsa.decifrar(Base64.getDecoder().decode(partes[2]));
        if (bytesAES.length != 32 || bytesHMAC.length != 32) {
            throw new IOException("Chaves de sessão inválidas.");
        }

        SecretKey chaveAES = new SecretKeySpec(bytesAES, "AES");
        byte[] mac = ImplHMAC.gerarMAC(session.getBytes(StandardCharsets.UTF_8), bytesHMAC);
        String macAssinadoBase64 = Base64.getEncoder().encodeToString(rsa.assinar(mac));
        resposta = "SESSION_OK|" + macAssinadoBase64;
        saida.write(resposta.getBytes(StandardCharsets.UTF_8));
        LOG.registrar("Origem", "Borda", "TCP ENVIO SESSION_OK", resposta);
        sessao.confirmar(chaveAES, bytesHMAC);
        LOG.registrar("Borda", "Origem", "SESSAO PRONTA", "Handshake AES/HMAC confirmado");
        System.out.println("Sessão AES/HMAC confirmada com Borda.");
        return sessao;
    }

    // Origem inicia uma sessão diferente na porta de invalidação da Borda.
    private SessaoSegura iniciarSessaoInvalidacao(InputStream entrada, OutputStream saida)
            throws IOException, GeneralSecurityException {
        String publicaOrigemBase64 = Base64.getEncoder().encodeToString(rsa.getChavePublica().getEncoded());
        String hello = "HELLO|" + publicaOrigemBase64;
        saida.write(hello.getBytes(StandardCharsets.UTF_8));
        LOG.registrar("Origem", "Borda", "TCP ENVIO HELLO", hello);

        byte[] buffer = new byte[4096];
        int bytesLidos = entrada.read(buffer);
        String mensagem = bytesLidos == -1 ? "" : new String(buffer, 0, bytesLidos, StandardCharsets.UTF_8);
        LOG.registrar("Borda", "Origem", "TCP RECEBIDO PUBLIC_KEY", mensagem);
        if (!mensagem.startsWith("PUBLIC_KEY|")) {
            throw new IOException("Pública da Borda não recebida.");
        }
        String publicaBordaBase64 = mensagem.substring("PUBLIC_KEY|".length());
        byte[] publicaBordaBytes = Base64.getDecoder().decode(publicaBordaBase64);
        PublicKey publicaBorda = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(publicaBordaBytes));

        KeyGenerator gerador = KeyGenerator.getInstance("AES");
        gerador.init(256);
        SecretKey chaveAES = gerador.generateKey();
        byte[] chaveHMAC = new byte[32];
        new SecureRandom().nextBytes(chaveHMAC);
        String chaveAESCifrada = Base64.getEncoder().encodeToString(
                rsa.cifrar(chaveAES.getEncoded(), publicaBorda));
        String chaveHMACCifrada = Base64.getEncoder().encodeToString(
                rsa.cifrar(chaveHMAC, publicaBorda));
        String session = "SESSION|" + chaveAESCifrada + "|" + chaveHMACCifrada;
        saida.write(session.getBytes(StandardCharsets.UTF_8));
        LOG.registrar("Origem", "Borda", "TCP ENVIO SESSION", session);

        buffer = new byte[4096];
        bytesLidos = entrada.read(buffer);
        String confirmacao = bytesLidos == -1 ? "" : new String(buffer, 0, bytesLidos, StandardCharsets.UTF_8);
        LOG.registrar("Borda", "Origem", "TCP RECEBIDO SESSION_OK", confirmacao);
        if (!confirmacao.startsWith("SESSION_OK|")) {
            throw new IOException("Borda não confirmou a sessão.");
        }
        byte[] mac = ImplHMAC.gerarMAC(session.getBytes(StandardCharsets.UTF_8), chaveHMAC);
        byte[] assinatura = Base64.getDecoder().decode(confirmacao.substring("SESSION_OK|".length()));
        if (!rsa.verificarAssinatura(mac, assinatura, publicaBorda)) {
            throw new SecurityException("HMAC/assinatura de SESSION_OK inválido.");
        }
        SessaoSegura sessao = new SessaoSegura(publicaBorda);
        sessao.confirmar(chaveAES, chaveHMAC);
        LOG.registrar("Borda", "Origem", "HMAC OK SESSION", "Handshake AES/HMAC confirmado");
        System.out.println("Sessão AES/HMAC confirmada com Borda para INVALIDATE.");
        return sessao;
    }

    private void invalidarCache(String nomeArquivo) {
        Socket borda = null;
        try {
            borda = new Socket("localhost", PORTA_INVALIDACAO_BORDA);
            OutputStream saida = borda.getOutputStream();
            InputStream entrada = borda.getInputStream();
            SessaoSegura sessao = iniciarSessaoInvalidacao(entrada, saida);

            String comando = EnvelopeSeguro.proteger("INVALIDATE /" + nomeArquivo, aes,
                    sessao.getChaveAES(), sessao.getChaveHMAC(), rsa);
            saida.write(comando.getBytes(StandardCharsets.UTF_8));
            LOG.registrar("Origem", "Borda", "TCP ENVIO INVALIDATE", comando);

            byte[] buffer = new byte[4096];
            int bytesLidos = entrada.read(buffer);
            if (bytesLidos == -1) {
                throw new IOException("Borda encerrou sem confirmar invalidação.");
            }
            String envelope = new String(buffer, 0, bytesLidos, StandardCharsets.UTF_8);
            LOG.registrar("Borda", "Origem", "TCP RECEBIDO INVALIDATED", envelope);
            String resposta = EnvelopeSeguro.abrir(envelope, aes, sessao.getChaveAES(),
                    sessao.getChaveHMAC(), rsa, sessao.getPublicaRemota());
            System.out.println("HMAC da Borda validado na confirmação.");
            LOG.registrar("Borda", "Origem", "HMAC OK INVALIDATED", resposta);
            if (("INVALIDATED /" + nomeArquivo).equals(resposta)) {
                System.out.println("Cache invalidado na borda: " + nomeArquivo);
            } else {
                System.out.println("[ERROR] Falha ao invalidar cache: " + resposta);
            }
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            LOG.registrar("Origem", "Borda", "FALHA INVALIDATE", e.getMessage());
            System.out.println("[ERROR] Falha na comunicação segura com a borda: " + e.getMessage());
        } finally {
            if (borda != null) {
                try {
                    borda.close();
                } catch (IOException e) {
                    System.out.println("Erro ao fechar conexão com a borda: " + e.getMessage());
                }
            }
        }
    }

    public static void main(String[] args){
        new ServidorOrigem();
    }
}
