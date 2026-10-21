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
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import utils.EnvelopeSeguro;
import utils.ImplAES256;
import utils.ImplHMAC;
import utils.ImplRSA;
import utils.SessaoSegura;

public class ServidorBorda {
    final private int PORTA_BORDA = 8003;
    final private int PORTA_INVALIDACAO = 8103;
    final private int PORTA_ORIGEM = 8000;
    private static final long TTL_NANOS = java.util.concurrent.TimeUnit.SECONDS.toNanos(10); // 10 segundos de TTL

    private static class EntradaCache {
        final String arquivo;
        final long criadaEm = System.nanoTime();

        EntradaCache(String arquivo) {
            this.arquivo = arquivo;
        }
    }

    private ConcurrentHashMap<String, EntradaCache> cache; // compartilhado com o listener de invalidações
    private final ImplAES256 aes = new ImplAES256();
    private ImplRSA rsa;

    public ServidorBorda(){
        cache = new ConcurrentHashMap<>();
        rodar();
    }

    private void rodar(){
        ServerSocket servidorBorda = null;
        try {
            rsa = new ImplRSA();
            servidorBorda = new ServerSocket(PORTA_BORDA);

            System.out.println("Servidor de borda rodando na porta " + PORTA_BORDA + "...");

            new Thread(new Runnable() {
                @Override
                public void run() {
                    ouvirInvalidacoes();
                }
            }).start();

            // busca novas conexões
            while (true){
                Socket cliente = servidorBorda.accept();

                try {
                    System.out.println("Cliente conectado: " + cliente.getInetAddress().getHostAddress());
                    
                    // como cliente só manda uma solicitação por vez, não precisa de thread nem laço 
                    InputStream entrada = cliente.getInputStream();
                    OutputStream saida = cliente.getOutputStream();
                    SessaoSegura sessao = iniciarSessao(entrada, saida);

                    // recebe mensagens de um cliente
                    byte[] buffer = new byte[4096];
                    int bytesLidos = entrada.read(buffer);

                    if (bytesLidos == -1){
                        System.out.println("Cliente desconectado: " + cliente.getInetAddress().getHostAddress());
                        continue;
                    }

                    if (bytesLidos > 0){
                        String envelope = new String(buffer, 0, bytesLidos, StandardCharsets.UTF_8);
                        // Autenticar antes de decifrar e acessar o cache; falha encerra conexão
                        String mensagemRecebida = EnvelopeSeguro.abrir(envelope, aes, sessao.getChaveAES(),
                                sessao.getChaveHMAC(), rsa, sessao.getPublicaRemota());
                        System.out.println("HMAC do Cliente validado.");
                        if (!mensagemRecebida.startsWith("GET /")){
                            System.out.println("Mensagem inválida recebida: " + mensagemRecebida);
                            String resposta = EnvelopeSeguro.proteger("[ERROR] Mensagem inválida", aes,
                                    sessao.getChaveAES(), sessao.getChaveHMAC(), rsa);
                            saida.write(resposta.getBytes(StandardCharsets.UTF_8));
                            continue;
                        }
                        
                        System.out.println("Mensagem recebida do cliente: " + mensagemRecebida);

                        String nomeArquivo = mensagemRecebida.substring(5); // remove GET /
                        String regraNomeArquivo = "arquivo(?:[1-9]\\d{0,2}|1000)\\.ext"; // arquivo1.ext até arquivo1000.ext, sem 0 à esquerda 

                        if (!nomeArquivo.matches(regraNomeArquivo)){
                            System.out.println("Nome de arquivo inválido recebido: " + nomeArquivo);
                            String resposta = EnvelopeSeguro.proteger("[ERROR] Nome de arquivo inválido", aes,
                                    sessao.getChaveAES(), sessao.getChaveHMAC(), rsa);
                            saida.write(resposta.getBytes(StandardCharsets.UTF_8));
                            continue;
                        }
                        String idArquivo = nomeArquivo.substring(7, nomeArquivo.length() - 4); // remove "arquivo" e ".ext"

                        // verifica cache hit ou miss
                        buscarNaCache(idArquivo, saida, sessao);
                    }
                } catch (Exception e){
                    System.out.println("Erro na conexão com o cliente: " + e.getMessage());
                } finally {
                    // fecha a conexão com o cliente
                    try {
                        cliente.close();
                    } catch (Exception e){
                        System.out.println("Erro ao fechar conexão com o cliente: " + e.getMessage());
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("Erro ao iniciar o servidor de borda: " + e.getMessage());
        } finally {
            if (servidorBorda != null){
                try {
                    servidorBorda.close();
                } catch (Exception e) {
                    System.out.println("Erro ao fechar o servidor de borda: " + e.getMessage());
                }
            }
        }
    }

    // Mesmo HELLO/PUBLIC_KEY/SESSION/SESSION_OK do GeoDNS, agora no TCP do Cliente
    private SessaoSegura iniciarSessao(InputStream entrada, OutputStream saida)
            throws IOException, GeneralSecurityException {
        byte[] buffer = new byte[4096];
        int bytesLidos = entrada.read(buffer);
        String hello = bytesLidos == -1 ? "" : new String(buffer, 0, bytesLidos, StandardCharsets.UTF_8);
        String[] partes = hello.split("\\|", -1);

        if (partes.length != 2 || !"HELLO".equals(partes[0])) {
            throw new IOException("HELLO inválido.");
        }

        byte[] publicaClienteBytes = Base64.getDecoder().decode(partes[1]);
        PublicKey publicaCliente = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(publicaClienteBytes));
        SessaoSegura sessao = new SessaoSegura(publicaCliente);
        String publicaBordaBase64 = Base64.getEncoder().encodeToString(rsa.getChavePublica().getEncoded());
        String resposta = "PUBLIC_KEY|" + publicaBordaBase64;
        saida.write(resposta.getBytes(StandardCharsets.UTF_8));

        buffer = new byte[4096];
        bytesLidos = entrada.read(buffer);
        String session = bytesLidos == -1 ? "" : new String(buffer, 0, bytesLidos, StandardCharsets.UTF_8);
        partes = session.split("\\|", -1);

        if (partes.length != 3 || !"SESSION".equals(partes[0])){
            throw new IOException("SESSION inválida.");
        }

        byte[] bytesAES = rsa.decifrar(Base64.getDecoder().decode(partes[1]));
        byte[] bytesHMAC = rsa.decifrar(Base64.getDecoder().decode(partes[2]));

        if (bytesAES.length != 32 || bytesHMAC.length != 32) {
            throw new IOException("Chaves de sessão inválidas.");
        }

        SecretKey chaveAES = new SecretKeySpec(bytesAES, "AES");
        byte[] mac = ImplHMAC.gerarMAC(session.getBytes(StandardCharsets.UTF_8), bytesHMAC);
        resposta = "SESSION_OK|" + Base64.getEncoder().encodeToString(rsa.assinar(mac));
        saida.write(resposta.getBytes(StandardCharsets.UTF_8));
        sessao.confirmar(chaveAES, bytesHMAC);
        System.out.println("Sessão AES/HMAC confirmada com Cliente.");
        return sessao;
    }

    // Origem inicia uma conexão TCP e envia uma linha: INVALIDATE /arquivoN.ext
    private void ouvirInvalidacoes() {
        ServerSocket servidorInvalidacao = null;
        try {
            servidorInvalidacao = new ServerSocket(PORTA_INVALIDACAO);
            // SEGURANÇA: esta porta também exige handshake RSA/AES/HMAC com Origem.
            System.out.println("Borda escutando invalidações na porta " + PORTA_INVALIDACAO + "...");
            while (true) {
                Socket origem = servidorInvalidacao.accept();
                // SEGURANÇA: vincular sessão à pública RSA da Origem antes de INVALIDATE.
                try {
                    InputStream entrada = origem.getInputStream();
                    OutputStream saida = origem.getOutputStream();

                    byte[] buffer = new byte[4096];
                    int bytesLidos = entrada.read(buffer);
                    // se bytesLidos == -1, a conexão foi fechada pelo cliente, então tratamos como uma string vazia
                    // se não, lemos a string normalment
                    // SEGURANÇA: validar assinatura/HMAC e decifrar ANTES de cache.remove;
                    // falha encerra conexão sem modificar cache.
                    String comando = bytesLidos == -1 ? "" : new String(buffer, 0, bytesLidos, StandardCharsets.UTF_8);

                    if (!comando.startsWith("INVALIDATE /")) {
                        saida.write("[ERROR] Comando de invalidação inválido\n".getBytes(StandardCharsets.UTF_8));
                        continue;
                    }
                    String nomeArquivo = comando.substring("INVALIDATE /".length());
                    if (!nomeArquivo.matches("arquivo(?:[1-9]\\d{0,2}|1000)\\.ext")) {
                        saida.write("[ERROR] Nome de arquivo inválido\n".getBytes(StandardCharsets.UTF_8));
                        continue;
                    }

                    String idArquivo = nomeArquivo.substring(7, nomeArquivo.length() - 4);
                    cache.remove(idArquivo);
                    System.out.println("Cache invalidado: " + nomeArquivo);
                    // SEGURANÇA: cifrar e autenticar também confirmação INVALIDATED.
                    saida.write(("INVALIDATED /" + nomeArquivo + "\n").getBytes(StandardCharsets.UTF_8));
                } catch (IOException e) {
                    System.out.println("Erro ao receber invalidação: " + e.getMessage());
                } finally {
                    try {
                        origem.close();
                    } catch (IOException e) {
                        System.out.println("Erro ao fechar conexão de invalidação: " + e.getMessage());
                    }
                }
            }
        } catch (IOException e) {
            System.out.println("Erro no listener de invalidações: " + e.getMessage());
        } finally {
            if (servidorInvalidacao != null) {
                try {
                    servidorInvalidacao.close();
                } catch (IOException e) {
                    System.out.println("Erro ao fechar listener de invalidações: " + e.getMessage());
                }
            }
        }
    }

    private void buscarNaCache(String idArquivo, OutputStream saida, SessaoSegura sessao)
            throws IOException, GeneralSecurityException {
        EntradaCache entrada = cache.get(idArquivo);
        if (entrada != null && System.nanoTime() - entrada.criadaEm >= TTL_NANOS) { // não é nulo e TTL expirou
            cache.remove(idArquivo);
            entrada = null;
            System.out.println("TTL expirado: arquivo" + idArquivo + ".ext");
        }

        if (entrada != null){
            System.out.println("Cache HIT!");
            String resposta = EnvelopeSeguro.proteger("HIT /" + entrada.arquivo, aes,
                    sessao.getChaveAES(), sessao.getChaveHMAC(), rsa);
            saida.write(resposta.getBytes(StandardCharsets.UTF_8));
        } else {
            String nomeArquivo = "arquivo" + idArquivo + ".ext";
            System.out.println("MISS para o arquivo: " + nomeArquivo);
            String resposta = EnvelopeSeguro.proteger("MISS /" + nomeArquivo, aes,
                    sessao.getChaveAES(), sessao.getChaveHMAC(), rsa);
            saida.write(resposta.getBytes(StandardCharsets.UTF_8));
            buscarNaOrigem(idArquivo, saida, sessao);
        }
    }

    // Borda inicia uma sessão TCP própria com Origem (distinta da sessão com Cliente).
    private SessaoSegura iniciarSessaoOrigem(InputStream entrada, OutputStream saida)
            throws IOException, GeneralSecurityException {
        String publicaBordaBase64 = Base64.getEncoder().encodeToString(rsa.getChavePublica().getEncoded());
        String hello = "HELLO|" + publicaBordaBase64;
        saida.write(hello.getBytes(StandardCharsets.UTF_8));

        byte[] buffer = new byte[4096];
        int bytesLidos = entrada.read(buffer);
        String mensagem = bytesLidos == -1 ? "" : new String(buffer, 0, bytesLidos, StandardCharsets.UTF_8);

        if (!mensagem.startsWith("PUBLIC_KEY|")){
            throw new IOException("Pública da Origem não recebida.");
        }
        String publicaOrigemBase64 = mensagem.substring("PUBLIC_KEY|".length());
        byte[] chaveBytes = Base64.getDecoder().decode(publicaOrigemBase64);
        PublicKey publicaOrigem = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(chaveBytes));

        KeyGenerator gerador = KeyGenerator.getInstance("AES");
        gerador.init(256);
        SecretKey chaveAES = gerador.generateKey();
        byte[] chaveHMAC = new byte[32];
        new SecureRandom().nextBytes(chaveHMAC);
        String chaveAESCifrada = Base64.getEncoder().encodeToString(
                rsa.cifrar(chaveAES.getEncoded(), publicaOrigem));
        String chaveHMACCifrada = Base64.getEncoder().encodeToString(
                rsa.cifrar(chaveHMAC, publicaOrigem));
        String session = "SESSION|" + chaveAESCifrada + "|" + chaveHMACCifrada;
        saida.write(session.getBytes(StandardCharsets.UTF_8));

        buffer = new byte[4096];
        bytesLidos = entrada.read(buffer);
        String confirmacao = bytesLidos == -1 ? "" : new String(buffer, 0, bytesLidos, StandardCharsets.UTF_8);
        
        if (!confirmacao.startsWith("SESSION_OK|")) {
            throw new IOException("Origem não confirmou a sessão.");
        } 
        byte[] mac = ImplHMAC.gerarMAC(session.getBytes(StandardCharsets.UTF_8), chaveHMAC);
        byte[] assinatura = Base64.getDecoder().decode(confirmacao.substring("SESSION_OK|".length()));

        if (!rsa.verificarAssinatura(mac, assinatura, publicaOrigem)) {
            throw new SecurityException("HMAC/assinatura de SESSION_OK inválido.");
        }
        SessaoSegura sessao = new SessaoSegura(publicaOrigem);
        sessao.confirmar(chaveAES, chaveHMAC);
        System.out.println("Sessão AES/HMAC confirmada com Origem.");
        return sessao;
    }

    private void buscarNaOrigem(String idArquivo, OutputStream saida, SessaoSegura sessaoCliente)
            throws IOException, GeneralSecurityException {
        Socket servidorOrigem = null;
        try {
            servidorOrigem = new Socket("localhost", PORTA_ORIGEM);
            OutputStream saidaOrigem = servidorOrigem.getOutputStream();
            InputStream entradaOrigem = servidorOrigem.getInputStream();
            SessaoSegura sessaoOrigem = iniciarSessaoOrigem(entradaOrigem, saidaOrigem);

            String pedido = EnvelopeSeguro.proteger("GET /arquivo" + idArquivo + ".ext", aes,
                    sessaoOrigem.getChaveAES(), sessaoOrigem.getChaveHMAC(), rsa);
            saidaOrigem.write(pedido.getBytes(StandardCharsets.UTF_8));

            byte[] buffer = new byte[4096];
            int bytesLidos = entradaOrigem.read(buffer);
            if (bytesLidos == -1) throw new IOException("Origem encerrou sem resposta.");
            String envelope = new String(buffer, 0, bytesLidos, StandardCharsets.UTF_8);
            // Verificar HMAC/assinatura antes de aceitar DATA ou alterar cache.
            String respostaOrigem = EnvelopeSeguro.abrir(envelope, aes, sessaoOrigem.getChaveAES(),
                    sessaoOrigem.getChaveHMAC(), rsa, sessaoOrigem.getPublicaRemota());
            System.out.println("HMAC da Origem validado.");
            if (!respostaOrigem.equals("DATA /arquivo" + idArquivo + ".ext")) {
                String erro = respostaOrigem.startsWith("[ERROR]") ? respostaOrigem : "[ERROR] Resposta inválida da origem";
                String protegido = EnvelopeSeguro.proteger(erro, aes,
                        sessaoCliente.getChaveAES(), sessaoCliente.getChaveHMAC(), rsa);
                saida.write(protegido.getBytes(StandardCharsets.UTF_8));
                return;
            }

            cache.put(idArquivo, new EntradaCache("arquivo" + idArquivo + ".ext"));
            String protegido = EnvelopeSeguro.proteger(respostaOrigem, aes,
                    sessaoCliente.getChaveAES(), sessaoCliente.getChaveHMAC(), rsa);
            saida.write(protegido.getBytes(StandardCharsets.UTF_8));
        } catch (IOException | GeneralSecurityException | SecurityException e) {
            System.out.println("Erro ao buscar na origem: " + e.getMessage());
            String protegido = EnvelopeSeguro.proteger("[ERROR] Comunicação segura com Origem falhou", aes,
                    sessaoCliente.getChaveAES(), sessaoCliente.getChaveHMAC(), rsa);
            saida.write(protegido.getBytes(StandardCharsets.UTF_8));
        } finally {
            if (servidorOrigem != null) {
                try {
                    servidorOrigem.close();
                } catch (IOException e) {
                    System.out.println("Erro ao fechar conexão com a Origem: " + e.getMessage());
                }
            }
        }
    }

    public static void main(String[] args) {
        new ServidorBorda();
    }
}
