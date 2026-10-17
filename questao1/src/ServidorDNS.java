import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ServidorDNS {
    final int PORTA_DNS = 5353;
    static Map<String, String> tabelaDNS;

    public ServidorDNS() {
        tabelaDNS = new ConcurrentHashMap<String, String>();

        for (int i = 0; i < 10; i++) {
            String nome = "servidor" + (i + 1);
            String enderecoIP = "192.168.0." + (i + 1);
            tabelaDNS.put(nome, enderecoIP);
        }

        rodar();
    }

    private void rodar() {
        ServerSocket servidorDNS = null;

        try {
            servidorDNS = new ServerSocket(PORTA_DNS);
            
            System.out.println("Servidor DNS rodando na porta " + PORTA_DNS + "...");
            
            // busca novas conexões
            while (true){
                Socket cliente = servidorDNS.accept();
                System.out.println("Cliente conectado: " + cliente.getInetAddress());
                
                // uma thread para cada cliente
                new Thread( new Runnable(){
                    @Override
                    public void run() {
                        try {
                            InputStream entrada = cliente.getInputStream();
                            OutputStream saida = cliente.getOutputStream();

                            // recebe mensagens de um cliente
                            while (true){
                                byte[] buffer = new byte[512];
                                int bytesLidos = entrada.read(buffer);

                                if (bytesLidos == -1) {
                                    System.out.println("Cliente desconectado: " + cliente.getInetAddress());
                                    break;
                                }
                                // se houve mensagem do cliente
                                if (bytesLidos > 0){
                                    String msgRecebida = new String(buffer, 0, bytesLidos, "UTF-8");
                                    System.out.println("Mensagem recebida: " + msgRecebida);

                                    String resposta = "Servidores: \n";

                                    // opções de operações solicitadas pelo cliente
                                    if (msgRecebida.startsWith("LIST")){
                                        for (Map.Entry<String, String> entry : tabelaDNS.entrySet()){
                                            resposta += entry.getKey() + " -> " + entry.getValue() + "\n";
                                        }
                                        saida.write(resposta.getBytes("UTF-8"));
                                        System.out.println("Listagem enviada ao cliente.");
                                    }
                                    else if (msgRecebida.startsWith("GET|")){
                                        String nomeServidor = msgRecebida.substring(4).trim();
                                        String enderecoIP = tabelaDNS.get(nomeServidor);
                                        if (enderecoIP != null){
                                            resposta = "Endereço IP de " + nomeServidor + ": " + enderecoIP;
                                        } else {
                                            resposta = nomeServidor + " não encontrado.";
                                        }
                                        saida.write(resposta.getBytes("UTF-8"));
                                    }
                                    // apenas cliente registrador; checar aqui também?
                                    else if (msgRecebida.startsWith("SET|")){
                                        String[] partes = msgRecebida.split("\\|");
                                        if (partes.length == 3){
                                            String nomeServidorSet = partes[1].trim();
                                            String novoEnderecoIP = partes[2].trim();
                                            tabelaDNS.put(nomeServidorSet, novoEnderecoIP);
                                            resposta = "Endereço IP de " + nomeServidorSet + " atualizado para: " + novoEnderecoIP;
                                        } else {
                                            resposta = "Formato inválido para SET. Use: SET|nomeServidor|novoEnderecoIP";
                                        }
                                        saida.write(resposta.getBytes("UTF-8"));
                                    }

                                    else if (msgRecebida.startsWith("QUIT")){
                                        System.out.println("O cliente " + cliente.getInetAddress() + " desconectou.");
                                        cliente.close();
                                        break;
                                    }
                        }
                    }
                    
                } catch (IOException e) {
                    System.err.println("Erro na comunicação com o cliente: " + e.getMessage());
                }
                    }
                }).start();
            }
        } catch (IOException e){
            System.err.println("Erro no servidor: " + e.getMessage());
        } finally {
            if (servidorDNS != null) {
                try {
                    servidorDNS.close();
                } catch (IOException e) {
                    System.err.println("Erro ao fechar o servidor: " + e.getMessage());
                }
            }
        }
    }

    public static void main(String[] args){
        new ServidorDNS();
    }
}
