import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import utils.EnvelopeSeguro;
import utils.ImplAES256;
import utils.ImplHMAC;
import utils.ImplRSA;
import utils.SessaoSegura;

public class Cliente {
    private final int PORTA_GEODNS = 5354;
    private String ipBorda;
    private int portaBorda;

    public Cliente() {
        rodar();
    }

    private void rodar() {
        Scanner teclado = new Scanner(System.in);
        while (true) {
            System.out.println("1 - LOCATE | 2 - GET | 0 - Encerrar cliente");
            if (!teclado.hasNextLine()) return;
            String opcao = teclado.nextLine().trim();

            switch (opcao) {
                case "0":
                    return;
                case "1":
                    localizarBorda();
                    break;
                case "2":
                    if (ipBorda == null) {
                        System.out.println("[ERROR] Consulte LOCATE antes de GET.");
                        break;
                    }
                    System.out.println("Nome do arquivo:");
                    if (!teclado.hasNextLine()) return;
                    String nomeArquivo = teclado.nextLine().trim();
                    if (!nomeArquivo.matches("arquivo(?:[1-9]\\d{0,2}|1000)\\.ext")) {
                        System.out.println("Erro na entrada de dados. Tente outra vez!");
                        break;
                    }
                    buscarArquivo(nomeArquivo);
                    break;
                default:
                    System.out.println("Opção inválida.");
            }
        }
    }

    private void localizarBorda() {
        DatagramSocket socket = null;
        ipBorda = null;
        portaBorda = 0;
        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(3000);
            InetAddress destino = InetAddress.getByName("localhost");
            socket.connect(destino, PORTA_GEODNS); // só recebe pacotes desse GeoDNS
            ImplRSA rsa = new ImplRSA();
            ImplAES256 aes = new ImplAES256();
            SessaoSegura sessao = iniciarSessao(socket, destino, rsa);

            String protegido = EnvelopeSeguro.proteger("LOCATE", aes, sessao.getChaveAES(), sessao.getChaveHMAC(), rsa);
            byte[] dados = protegido.getBytes(StandardCharsets.UTF_8);
            socket.send(new DatagramPacket(dados, dados.length, destino, PORTA_GEODNS));

            byte[] buffer = new byte[4096];
            DatagramPacket resposta = new DatagramPacket(buffer, buffer.length);
            socket.receive(resposta);
            String envelope = new String(buffer, 0, resposta.getLength(), StandardCharsets.UTF_8);
            String mensagem = EnvelopeSeguro.abrir(envelope, aes, sessao.getChaveAES(),sessao.getChaveHMAC(), rsa, sessao.getPublicaRemota());
            System.out.println("HMAC validado na resposta do GeoDNS.");
            if (!mensagem.startsWith("LOCATION /")) {
                System.out.println(mensagem);
                return;
            }

            String[] endereco = mensagem.substring("LOCATION /".length()).split(":", -1);
            if (endereco.length != 2 || endereco[0].isEmpty()) {
                System.out.println("[ERROR] Endereço da borda inválido.");
                return;
            }
            int porta = Integer.parseInt(endereco[1]);
            if (porta < 1 || porta > 65535) {
                System.out.println("[ERROR] Porta da borda inválida.");
                return;
            }
            ipBorda = endereco[0];
            portaBorda = porta;
            System.out.println("Borda localizada: " + ipBorda + ":" + portaBorda);
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            System.out.println("[ERROR] Falha no LOCATE: " + e.getMessage());
        } finally {
            if (socket != null) socket.close();
        }
    }

    // Handshake UDP com GeoDNS
    private SessaoSegura iniciarSessao(DatagramSocket socket, InetAddress destino, ImplRSA rsa)
            throws IOException, GeneralSecurityException {
        String hello = "HELLO|" + Base64.getEncoder().encodeToString(rsa.getChavePublica().getEncoded());
        byte[] dados = hello.getBytes(StandardCharsets.UTF_8);
        socket.send(new DatagramPacket(dados, dados.length, destino, PORTA_GEODNS));

        byte[] buffer = new byte[4096];
        DatagramPacket resposta = new DatagramPacket(buffer, buffer.length);
        socket.receive(resposta);

        String mensagem = new String(buffer, 0, resposta.getLength(), StandardCharsets.UTF_8);
        if (!mensagem.startsWith("PUBLIC_KEY|")){ 
            throw new IOException("Pública do GeoDNS não recebida."); 
        }

        String chaveExtraidaString = mensagem.substring("PUBLIC_KEY|".length()); // Extrai a chave pública do GeoDNS da resposta recebida
        byte[] chaveExtraidaBytes = Base64.getDecoder().decode(chaveExtraidaString); // converte pra bytes pra geração de PublicKey

        PublicKey publicaGeoDNS = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(chaveExtraidaBytes));

        KeyGenerator gerador = KeyGenerator.getInstance("AES");
        gerador.init(256);
        SecretKey chaveAES = gerador.generateKey();
        byte[] chaveHMAC = new byte[32];
        new SecureRandom().nextBytes(chaveHMAC);

        String chaveAESCifrada = Base64.getEncoder().encodeToString(rsa.cifrar(chaveAES.getEncoded(), publicaGeoDNS));
        String chaveHMACCifrada = Base64.getEncoder().encodeToString(rsa.cifrar(chaveHMAC, publicaGeoDNS));

        String session = "SESSION|" + chaveAESCifrada + "|" + chaveHMACCifrada;

        dados = session.getBytes(StandardCharsets.UTF_8);
        socket.send(new DatagramPacket(dados, dados.length, destino, PORTA_GEODNS));

        // envia sessão e espera OK
        buffer = new byte[4096];
        resposta = new DatagramPacket(buffer, buffer.length);
        socket.receive(resposta);
        String confirmacao = new String(buffer, 0, resposta.getLength(), StandardCharsets.UTF_8);

        if (!confirmacao.startsWith("SESSION_OK|")) {
            throw new IOException("GeoDNS não confirmou a sessão.");
        
        }
        byte[] mac = ImplHMAC.gerarMAC(session.getBytes(StandardCharsets.UTF_8), chaveHMAC);
        byte[] assinatura = Base64.getDecoder().decode(confirmacao.substring("SESSION_OK|".length()));

        // assinatura inválida gera exceção e encerra
        if (!rsa.verificarAssinatura(mac, assinatura, publicaGeoDNS)) {
            throw new SecurityException("HMAC/assinatura de SESSION_OK inválido.");
        }
        SessaoSegura sessao = new SessaoSegura(publicaGeoDNS);
        sessao.confirmar(chaveAES, chaveHMAC);
        return sessao;
    }

    private void buscarArquivo(String nomeArquivo) {
        Socket borda = null;
        try {
            borda = new Socket(ipBorda, portaBorda);
            InputStream entrada = borda.getInputStream();
            OutputStream saida = borda.getOutputStream();

            //handshake RSA/AES/HMAC com Borda antes do GET
            byte[] pedido = ("GET /" + nomeArquivo).getBytes(StandardCharsets.UTF_8);

            // GET cifrado com AES e HMAC assinado pela RSA do Cliente.
            saida.write(pedido);

            // resposta do servidor de borda
            byte[] buffer = new byte[4096];
            String resposta = "";
            int bytesLidos = entrada.read(buffer);
            while (bytesLidos != -1) {
                resposta += new String(buffer, 0, bytesLidos, StandardCharsets.UTF_8);
                bytesLidos = entrada.read(buffer);
            }
            // valida assinatura/HMAC e decifra HIT, MISS, DATA ou [ERROR]
            // antes de interpretar/exibir; rejeitar resposta adulterada
            System.out.println(resposta.trim()); 
        } catch (IOException e) {
            System.out.println("[ERROR] Falha no GET: " + e.getMessage());
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

    public static void main(String[] args) {
        new Cliente();
    }
}
