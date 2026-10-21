import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class GeoDNS {
    private final int PORTA_GEODNS = 5354;
    private final Map<String, Integer> bordasPorRegiao = new HashMap<>();

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
            socket = new DatagramSocket(PORTA_GEODNS);
            // SEGURANÇA: gerar par RSA do GeoDNS e manter sessões AES/HMAC por cliente UDP
            // (endereço + porta), como no ServidorDNS da questão 1.
            System.out.println("GeoDNS rodando na porta " + PORTA_GEODNS + "...");

            while (true) {
                byte[] buffer = new byte[4096];
                DatagramPacket pedido = new DatagramPacket(buffer, buffer.length);
                socket.receive(pedido);
                // SEGURANÇA: tratar HELLO/SESSION RSA; para LOCATE, validar HMAC e
                // assinatura da sessão antes de decifrar/processar. Descartar pacote inválido.

                String mensagem = new String(pedido.getData(), 0, pedido.getLength(), StandardCharsets.UTF_8);
                System.out.println("Consulta de " + pedido.getAddress().getHostAddress() + ": " + mensagem);

                String resposta = localizarBorda(mensagem);
                // SEGURANÇA: cifrar LOCATION/[ERROR] com AES; assinar RSA o HMAC do cifrado
                // usando chaves da sessão desse cliente antes de montar o datagrama.
                byte[] dados = resposta.getBytes(StandardCharsets.UTF_8);
                DatagramPacket pacoteResposta = new DatagramPacket(dados, dados.length, pedido.getAddress(), pedido.getPort());
                
                socket.send(pacoteResposta);
                System.out.println("Resposta enviada: " + resposta);
            }
        } catch (IOException e) {
            System.out.println("Erro no GeoDNS: " + e.getMessage());
        } finally {
            if (socket != null) socket.close();
        }
    }

    // LOCATE descobre a borda atual; localização opcional fica disponível para testes futuros.
    private String localizarBorda(String mensagem) {
        if ("LOCATE".equals(mensagem)) return "LOCATION /127.0.0.1:8003";
        if (!mensagem.startsWith("LOCATE /")) return "[ERROR] Comando inválido";

        String[] partes = mensagem.substring("LOCATE /".length()).split("\\|", -1);
        if (partes.length != 2 || !partes[0].matches("arquivo(?:[1-9]\\d{0,2}|1000)\\.ext")) {
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
