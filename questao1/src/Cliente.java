import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import utils.ImplAES256;
import utils.ImplHMAC;
import utils.ImplRSA;

public class Cliente {
    private boolean isRegistrador;
    DatagramSocket socket = null;
    private final int PORTA_DNS = 5959;

    public Cliente(boolean isRegistrador) {
        this.isRegistrador = isRegistrador;
        rodar();
    }

    private void rodar() {
        try {
            // supondo que o cliente já conhece o endereço IP e a porta do DNS
            socket = new DatagramSocket();
            InetAddress enderecoServidor = InetAddress.getByName("localhost");

            ImplRSA rsa = new ImplRSA(); // gera o par RSA do cliente
            ImplAES256 aes = new ImplAES256();
            SecretKey chaveAES = gerarChaveAES();
            byte[] chaveHMAC = gerarChaveHMAC();

            // Troca inicial de chaves públicas sem assinatura por enquanto.
            // Só a thread principal recebe pacotes até o fim dessa troca.
            iniciarSessao(enderecoServidor, rsa, chaveAES, chaveHMAC);

            // blocking queue para armazenar respostas do servidor
            // e mostrá-las na ordem correta na tela do cliente
            BlockingQueue<String> filaRespostas = new LinkedBlockingDeque<>();

            // thread para ouvir mensagens do servidor
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        while (true) {
                            byte[] buffer = new byte[4096];
                            DatagramPacket pacoteRecebido = new DatagramPacket(buffer, buffer.length);
                            socket.receive(pacoteRecebido);

                            String envelope = new String(buffer, 0, pacoteRecebido.getLength(), StandardCharsets.UTF_8);
                            try {
                                // HMAC é verificado antes de decifrar com AES.
                                String mensagemRecebida = verificarEDecifrar(envelope, aes, chaveAES, chaveHMAC);

                                if (mensagemRecebida == null) {
                                    System.err.println("[ERROR] HMAC inválido. Mensagem ignorada.");
                                    continue;
                                }

                                if (mensagemRecebida.startsWith("NOTIFY|")) {
                                    System.out.println("\n[NOTIFICAÇÃO]: " + mensagemRecebida.substring(7) + "\n");
                                } else {
                                    filaRespostas.offer(mensagemRecebida);
                                }
                            } catch (RuntimeException e) {
                                // Dados inválidos não devem encerrar a thread que recebe notificações.
                                System.err.println("Mensagem recebida inválida: " + e.getMessage());
                            }
                        }
                    } catch (IOException | GeneralSecurityException e) {
                        if (!socket.isClosed()) {
                            System.err.println("Erro ao escutar servidor: " + e.getMessage());
                        }
                    }
                }
            }).start();

            @SuppressWarnings("resource")
            Scanner teclado = new Scanner(System.in);

            // loop para enviar mensagens ao servidor
            while (true) {
                menu();
                String operacao = teclado.nextLine();
                String resposta = "";

                switch (operacao) {
                    case "0":
                        resposta = "LIST";
                        break;
                    case "1":
                        System.out.println("Qual o servidor?");
                        String nomeServidor = teclado.nextLine();
                        resposta = "GET|" + nomeServidor;
                        break;
                    // exige cliente registrador; servidor também precisará validar autorização
                    case "2":
                        if (!isRegistrador) {
                            System.out.println("[ERROR] Apenas registradores podem definir endereços IP.\n");
                            operacao = null;
                            break;
                        }
                        System.out.println("Qual o servidor?");
                        String nomeServidorSet = teclado.nextLine();
                        System.out.println("Qual o novo endereço IP?");
                        String enderecoIP = teclado.nextLine();
                        resposta = "SET|" + nomeServidorSet + "|" + enderecoIP;
                        break;
                    case "3":
                        resposta = "QUIT";
                        break;
                    default:
                        System.out.println("[ERROR] Operação inválida. Tente novamente.");
                        operacao = null;
                        break;
                }

                if (operacao == null) continue;

                // Constrói mensagem completa antes do envio
                String mensagemSegura = cifrarEAutenticar(resposta, aes, chaveAES, chaveHMAC);
                byte[] dados = mensagemSegura.getBytes(StandardCharsets.UTF_8);
                DatagramPacket pacoteResposta = new DatagramPacket(dados, dados.length, enderecoServidor, PORTA_DNS);
                socket.send(pacoteResposta);

                if ("QUIT".equals(resposta)) {
                    socket.close();
                    return;
                }

                // usa uma blocking queue pra esperar a resposta do servidor
                // presente exclusivamente por organização visual
                try {
                    String mensagemDoServidor = filaRespostas.poll(3, TimeUnit.SECONDS);
                    if (mensagemDoServidor == null) {
                        System.out.println("[ERROR] Tempo de resposta do servidor excedido. Tente novamente.");
                    } else {
                        System.out.println("Resposta do servidor:\n" + mensagemDoServidor);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            System.err.println("Erro ao se comunicar com servidor: " + e.getMessage());
        } finally {
            if (socket != null) socket.close();
        }
    }

    private SecretKey gerarChaveAES() throws GeneralSecurityException {
        KeyGenerator gerador = KeyGenerator.getInstance("AES");
        gerador.init(256);
        return gerador.generateKey();
    }

    private byte[] gerarChaveHMAC() {
        byte[] chave = new byte[32];
        new SecureRandom().nextBytes(chave);
        return chave;
    }

    // handshake inicial para conversa segura com servidor
    private void iniciarSessao(InetAddress enderecoServidor, ImplRSA rsa, SecretKey chaveAES, byte[] chaveHMAC) throws IOException, GeneralSecurityException {
        
        // HELLO troca a chave pública RSA deste cliente
        String chavePublicaCliente = Base64.getEncoder().encodeToString(rsa.getChavePublica().getEncoded());
        String hello = "HELLO|" + chavePublicaCliente;
        byte[] dadosHello = hello.getBytes(StandardCharsets.UTF_8);
        socket.send(new DatagramPacket(dadosHello, dadosHello.length, enderecoServidor, PORTA_DNS));

        byte[] buffer = new byte[4096];
        DatagramPacket pacoteRecebido = new DatagramPacket(buffer, buffer.length);
        socket.receive(pacoteRecebido);

        // recebendo chave RSA pública do servidor
        String resposta = new String(buffer, 0, pacoteRecebido.getLength(), StandardCharsets.UTF_8);

        if (!resposta.startsWith("PUBLIC_KEY|")) {
            throw new IOException("Chave pública do servidor não recebida.");
        }
        byte[] chavePublicaBytes = Base64.getDecoder().decode(resposta.substring(11));
        PublicKey chavePublicaServidor = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(chavePublicaBytes));

        // troca de chave simétrica e HMAC no formato: SESSION|<chave AES cifrada com RSA>|<chave HMAC cifrada com RSA>
        byte[] aesCifrada = rsa.cifrar(chaveAES.getEncoded(), chavePublicaServidor);
        byte[] hmacCifrada = rsa.cifrar(chaveHMAC, chavePublicaServidor);
        String sessao = "SESSION|" + Base64.getEncoder().encodeToString(aesCifrada) + "|" + Base64.getEncoder().encodeToString(hmacCifrada);
        byte[] dadosSessao = sessao.getBytes(StandardCharsets.UTF_8);

        socket.send(new DatagramPacket(dadosSessao, dadosSessao.length, enderecoServidor, PORTA_DNS));

        // Servidor confirma que recuperou HMAC verificando o texto exato do SESSION
        buffer = new byte[4096];
        pacoteRecebido = new DatagramPacket(buffer, buffer.length);
        socket.receive(pacoteRecebido);
        String confirmacao = new String(buffer, 0, pacoteRecebido.getLength(), StandardCharsets.UTF_8);
        confirmarSessao(sessao, confirmacao, chaveHMAC);
    }

    // confirma que o servidor recebeu a sessão corretamente e que o HMAC bate com o esperado
    private void confirmarSessao(String sessao, String confirmacao, byte[] chaveHMAC)
            throws GeneralSecurityException, IOException {
        if (!confirmacao.startsWith("SESSION_OK|")) {
            throw new IOException("Servidor não confirmou a sessão.");
        }
        byte[] macRecebido = Base64.getDecoder().decode(confirmacao.substring(11));
        if (!ImplHMAC.verificarMAC(sessao.getBytes(StandardCharsets.UTF_8), chaveHMAC, macRecebido)) {
            throw new IOException("HMAC da confirmação da sessão inválido.");
        }
    }

    private String cifrarEAutenticar(String mensagem, ImplAES256 aes, SecretKey chaveAES, byte[] chaveHMAC) throws GeneralSecurityException {
        byte[] cifrado = aes.cifrar(mensagem, chaveAES);
        String conteudo = "DATA|" + Base64.getEncoder().encodeToString(cifrado);
        byte[] mac = ImplHMAC.gerarMAC(conteudo.getBytes(StandardCharsets.UTF_8), chaveHMAC);
        return conteudo + "|" + Base64.getEncoder().encodeToString(mac);
    }

    private String verificarEDecifrar(String envelope, ImplAES256 aes, SecretKey chaveAES, byte[] chaveHMAC) throws GeneralSecurityException {
        String[] partes = envelope.split("\\|", -1);
        if (partes.length != 3 || !"DATA".equals(partes[0])) {
            throw new IllegalArgumentException("Formato de envelope inválido.");
        }

        String conteudo = partes[0] + "|" + partes[1];
        byte[] macRecebido = Base64.getDecoder().decode(partes[2]);
        if (!ImplHMAC.verificarMAC(conteudo.getBytes(StandardCharsets.UTF_8), chaveHMAC, macRecebido)) {
            return null;
        }
        byte[] cifrado = Base64.getDecoder().decode(partes[1]);
        return new String(aes.decifrar(cifrado, chaveAES), StandardCharsets.UTF_8);
    }

    private void menu() {
        System.out.println("OPERAÇÕES DO MINI DNS:");
        System.out.println(
                "0 - LIST (listar servidores registrados no DNS)\n" +
                "1 - GET (obter endereço de servidor por nome)\n" +
                "2 - SET (definir endereço de servidor por nome)\n" +
                "3 - QUIT (encerrar conexão)");
        System.out.println("Selecione uma operação: ");
    }

    public static void main(String[] args) {
        new Cliente(true);
        //new Cliente(false);
    }
}
