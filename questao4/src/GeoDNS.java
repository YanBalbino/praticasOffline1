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
        bordasPorRegiao.put("NORTE", 8001);
        bordasPorRegiao.put("CENTRO", 8002);
        bordasPorRegiao.put("SUL", 8003);
        rodar();
    }

    private void rodar() {
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket(PORTA_GEODNS);
            System.out.println("GeoDNS rodando na porta " + PORTA_GEODNS + "...");

            while (true) {
                byte[] buffer = new byte[4096];
                DatagramPacket pedido = new DatagramPacket(buffer, buffer.length);
                socket.receive(pedido);

                String mensagem = new String(pedido.getData(), 0, pedido.getLength(), StandardCharsets.UTF_8);
                System.out.println("Consulta de " + pedido.getAddress().getHostAddress() + ": " + mensagem);

                String resposta = localizarBorda(mensagem);
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

    // LOCATE /arquivo20.ext|NORTE: arquivo desejado e localização fictícia do cliente.
    private String localizarBorda(String mensagem) {
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
