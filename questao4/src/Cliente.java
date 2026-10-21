import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

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
        try {
            socket = new DatagramSocket();
            // SEGURANÇA: antes do LOCATE, HELLO/SESSION RSA com GeoDNS neste socket UDP;
            // trocar apenas públicas RSA e chaves simétricas AES/HMAC cifradas, nunca privada RSA.
            socket.setSoTimeout(3000);
            byte[] dados = "LOCATE".getBytes(StandardCharsets.UTF_8);
            InetAddress destino = InetAddress.getByName("localhost");
            // SEGURANÇA: cifrar LOCATE com AES, HMAC do cifrado e assinatura RSA do HMAC.
            socket.send(new DatagramPacket(dados, dados.length, destino, PORTA_GEODNS));

            byte[] buffer = new byte[4096];
            DatagramPacket resposta = new DatagramPacket(buffer, buffer.length);
            socket.receive(resposta);
            // SEGURANÇA: validar HMAC/assinatura do GeoDNS antes de decifrar LOCATION.
            String mensagem = new String(buffer, 0, resposta.getLength(), StandardCharsets.UTF_8);
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
        } catch (IOException | NumberFormatException e) {
            System.out.println("[ERROR] Falha no LOCATE: " + e.getMessage());
        } finally {
            if (socket != null) socket.close();
        }
    }

    private void buscarArquivo(String nomeArquivo) {
        Socket borda = null;
        try {
            borda = new Socket(ipBorda, portaBorda);
            // SEGURANÇA: handshake RSA/AES/HMAC com esta Borda antes do GET.
            byte[] pedido = ("GET /" + nomeArquivo).getBytes(StandardCharsets.UTF_8);
            // SEGURANÇA: enviar GET cifrado com AES e HMAC assinado pela RSA do Cliente.
            borda.getOutputStream().write(pedido);

            InputStream entrada = borda.getInputStream();
            byte[] buffer = new byte[4096];
            String resposta = "";
            int bytesLidos = entrada.read(buffer);
            while (bytesLidos != -1) {
                resposta += new String(buffer, 0, bytesLidos, StandardCharsets.UTF_8);
                bytesLidos = entrada.read(buffer);
            }
            // SEGURANÇA: validar assinatura/HMAC e decifrar cada HIT, MISS, DATA ou [ERROR]
            // antes de interpretar/exibir; rejeitar resposta adulterada.
            System.out.println(resposta.trim()); // exibe a resposta do servidor de borda
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
