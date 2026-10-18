import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class ServidorDNS {
    final int PORTA_DNS = 5353;
    static Map<String, String> tabelaDNS;
    static List<Socket> clientesConectados;

    public ServidorDNS() {
        tabelaDNS = new ConcurrentHashMap<String, String>();
        clientesConectados = new CopyOnWriteArrayList<Socket>();

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

                // adiciona o socket do cliente à lista de clientes conectados
                clientesConectados.add(cliente);

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
                                    
                                    // [CRIPTO] decriptografia aqui
                                    
                                    System.out.println("Mensagem recebida: " + msgRecebida);

                                    String resposta = "";

                                    // opções de operações solicitadas pelo cliente
                                    if (msgRecebida.startsWith("LIST")){
                                        resposta = "Servidores:\n";

                                        for (Map.Entry<String, String> entry : tabelaDNS.entrySet()){
                                            resposta += entry.getKey() + " -> " + entry.getValue() + "\n";
                                        }
                                        resposta += "\n";

                                        //TODO jogar esse print pra depois do write
                                        System.out.println("Listagem enviada ao cliente.");
                                    }
                                    else if (msgRecebida.startsWith("GET|")){
                                        String nomeServidor = msgRecebida.substring(4).trim();
                                        String enderecoIP = tabelaDNS.get(nomeServidor);

                                        if (enderecoIP != null) resposta = "Endereço IP de " + nomeServidor + ": " + enderecoIP;
                                        else resposta = nomeServidor + " não encontrado.";

                                        //TODO jogar esse print pra depois do write
                                        System.out.println("Endereço de servidor enviado ao cliente.");
                                    }

                                    else if (msgRecebida.startsWith("SET|")){
                                        String[] partes = msgRecebida.split("\\|");
                                        if (partes.length == 3){
                                            String nomeServidorSet = partes[1].trim();
                                            String novoEnderecoIP = partes[2].trim();

                                            String ipAntigo = tabelaDNS.get(nomeServidorSet);

                                            if (ipAntigo == null) {
                                                //caso onde a resposta precisa ser enviada antes do loop reiniciar
                                                resposta = "Servidor " + nomeServidorSet + " não encontrado."; 
                                                
                                                // [CRIPTO] criptografia aqui

                                                saida.write(resposta.getBytes("UTF-8"));
                                                continue;
                                            }

                                            tabelaDNS.put(nomeServidorSet, novoEnderecoIP);
                                            resposta = "Endereço IP de " + nomeServidorSet + " atualizado para: " + novoEnderecoIP;
                                            resposta += "\n";

                                            //TODO criar um print dessa operação pra depois do write

                                            //TODO jogar essa notificação pra depois do write
                                            //método para notificar clientes conectados sobre atualização de IP
                                            notificarClientes(nomeServidorSet, ipAntigo, novoEnderecoIP);

                                        } else {
                                            resposta = "Erro: Formato inválido para SET. Use: SET|nomeServidor|novoEnderecoIP";
                                        }
                                    }

                                    else if (msgRecebida.startsWith("QUIT")){
                                        // caso onde a resposta precisa  ser enviada antes do cliente sair
                                        resposta = "NOTIFY|Desconectando do servidor...\n";

                                        // [CRIPTO] criptografia aqui

                                        saida.write(resposta.getBytes("UTF-8"));
                                        cliente.close();

                                        System.out.println("O cliente " + cliente.getInetAddress() + " desconectou.");
                                        break;
                                    }    

                                    // [CRIPTO] criptografia aqui
                                    
                                    //TODO criar um seletor de prints pós write
                                    saida.write(resposta.getBytes("UTF-8"));
                                } 
                            }
                        }
                            catch (IOException e) {
                        System.err.println("Erro na comunicação com o cliente: " + e.getMessage());}
                        finally{
                            clientesConectados.remove(cliente);
                            try {
                                cliente.close();
                            } catch (IOException e) {
                                System.err.println("Erro ao fechar o socket do cliente: " + e.getMessage());    
                            }
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

    private void notificarClientes(String nomeServidor, String ipAntigo, String novoEnderecoIP){
        String notificacao = "NOTIFY|ALTERACAO DE IP|" + nomeServidor + "|" + ipAntigo + "->" + novoEnderecoIP;
        // Enviar notificação para todos os clientes conectados
        for (Socket cliente : clientesConectados){
            try {
                OutputStream saida = cliente.getOutputStream();

                // [CRIPTO] criptografia aqui

                saida.write(notificacao.getBytes("UTF-8"));
            } catch (IOException e) {
                System.err.println("Erro ao notificar cliente: " + e.getMessage());
            }
        }
    }

    public static void main(String[] args){
        new ServidorDNS();
    }
}
