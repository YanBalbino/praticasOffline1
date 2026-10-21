import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import utils.EnvelopeSeguro;
import utils.ImplAES256;
import utils.ImplHMAC;
import utils.ImplRSA;
import utils.SessaoSegura;

public class GeoDNS {
    private final int PORTA_GEODNS = 5354;
    private final Map<String, Integer> bordasPorRegiao = new HashMap<>();
    private final Map<InetSocketAddress, SessaoSegura> sessoes = new HashMap<>();
    private final ImplAES256 aes = new ImplAES256();
    private ImplRSA rsa;

    public GeoDNS() {
        // simula diferentes localizações com diferentes portas de borda
        bordasPorRegiao.put("NORTE", 8001);
        bordasPorRegiao.put("CENTRO", 8002);
        bordasPorRegiao.put("SUL", 8003); // na prática usaremos essa
        rodar();
    }

    private void rodar() {
        DatagramSocket socket = null;
        try {
            rsa = new ImplRSA();
            socket = new DatagramSocket(PORTA_GEODNS);
            System.out.println("GeoDNS rodando na porta " + PORTA_GEODNS + "...");

            while (true) {
                byte[] buffer = new byte[4096];
                DatagramPacket pedido = new DatagramPacket(buffer, buffer.length);
                try {
                    socket.receive(pedido);
                    InetSocketAddress origem = new InetSocketAddress(pedido.getAddress(), pedido.getPort());
                    String mensagem = new String(pedido.getData(), 0, pedido.getLength(), StandardCharsets.UTF_8);

                    if (mensagem.startsWith("HELLO|")) {
                        receberHello(mensagem, origem, socket);
                    } else if (mensagem.startsWith("SESSION|")) {
                        receberSessao(mensagem, origem, socket);
                    } else {
                        SessaoSegura sessao = sessoes.get(origem);
                        if (sessao == null || !sessao.pronta()) {
                            System.out.println("Pacote descartado: cliente sem sessão: " + origem);
                            continue;
                        }
                        // HMAC e assinatura são validados antes da decifragem e do LOCATE.
                        String comando = EnvelopeSeguro.abrir(mensagem, aes, sessao.getChaveAES(),
                                sessao.getChaveHMAC(), rsa, sessao.getPublicaRemota());
                        System.out.println("HMAC validado de " + origem + ": " + comando);
                        String resposta = localizarBorda(comando);
                        String protegido = EnvelopeSeguro.proteger(resposta, aes, sessao.getChaveAES(),
                                sessao.getChaveHMAC(), rsa);
                        byte[] dados = protegido.getBytes(StandardCharsets.UTF_8);
                        socket.send(new DatagramPacket(dados, dados.length, origem.getAddress(), origem.getPort()));
                        System.out.println("Resposta segura enviada: " + resposta);
                    }
                } catch (IOException | GeneralSecurityException | RuntimeException e) {
                    System.out.println("Pacote rejeitado: " + e.getMessage());
                }
            }
        } catch (IOException | GeneralSecurityException e) {
            System.out.println("Erro no GeoDNS: " + e.getMessage());
        } finally {
            if (socket != null) socket.close();
        }
    }

    private void receberHello(String mensagem, InetSocketAddress origem, DatagramSocket socket)
            throws IOException, GeneralSecurityException {
        String[] partes = mensagem.split("\\|", -1);
        if (partes.length != 2) throw new IllegalArgumentException("HELLO inválido.");

        PublicKey publicaCliente = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(partes[1])));
        sessoes.put(origem, new SessaoSegura(publicaCliente));
        String resposta = "PUBLIC_KEY|" + Base64.getEncoder().encodeToString(rsa.getChavePublica().getEncoded());
        byte[] dados = resposta.getBytes(StandardCharsets.UTF_8);
        socket.send(new DatagramPacket(dados, dados.length, origem.getAddress(), origem.getPort()));

        System.out.println("HELLO recebido de " + origem);
    }

    private void receberSessao(String mensagem, InetSocketAddress origem, DatagramSocket socket) throws IOException, GeneralSecurityException {
        SessaoSegura sessao = sessoes.get(origem);
        if (sessao == null) throw new IllegalArgumentException("SESSION sem HELLO.");

        String[] partes = mensagem.split("\\|", -1);
        if (partes.length != 3) throw new IllegalArgumentException("SESSION inválida.");

        byte[] bytesAES = rsa.decifrar(Base64.getDecoder().decode(partes[1]));
        byte[] bytesHMAC = rsa.decifrar(Base64.getDecoder().decode(partes[2]));
        if (bytesAES.length != 32 || bytesHMAC.length != 32) {
            throw new IllegalArgumentException("Tamanho de chave de sessão inválido.");
        }
        SecretKey chaveAES = new SecretKeySpec(bytesAES, "AES");
        byte[] mac = ImplHMAC.gerarMAC(mensagem.getBytes(StandardCharsets.UTF_8), bytesHMAC);
        String resposta = "SESSION_OK|" + Base64.getEncoder().encodeToString(rsa.assinar(mac));
        byte[] dados = resposta.getBytes(StandardCharsets.UTF_8);
        socket.send(new DatagramPacket(dados, dados.length, origem.getAddress(), origem.getPort()));
        sessao.confirmar(chaveAES, bytesHMAC);
        
        System.out.println("Sessão AES/HMAC confirmada com " + origem);
    }

    // LOCATE descobre a borda atual; localização opcional fica disponível para testes futuros
    private String localizarBorda(String mensagem) {
        if ("LOCATE".equals(mensagem)) return "LOCATION /127.0.0.1:8003";
        if (!mensagem.startsWith("LOCATE /")) return "[ERROR] Comando inválido";

        String[] partes = mensagem.substring("LOCATE /".length()).split("\\|", -1);
        if (partes.length != 2 || !partes[0].matches("arquivo(?:[1-9]\\d{0,2}|1000)\\.ext")) { // se não é do padrão "arquivoX.ext" com X de 1 a 1000
            return "[ERROR] Nome de arquivo inválido";
        }
        Integer portaBorda = bordasPorRegiao.get(partes[1]);
        if (portaBorda == null) return "[ERROR] Localização inválida";

        return "LOCATION /127.0.0.1:" + portaBorda;
    }

    public static void main(String[] args) {
        new GeoDNS();
    }
}
