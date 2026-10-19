import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class ServidorDNS {
    static HashMap<String, String> tabelaDNS;
    static Set<InetSocketAddress> clientesConectados; // guardar IP e porta dos clientes conectados

    final int PORTA_DNS = 5959;
    InetAddress host;
    DatagramSocket socket = null;

    public ServidorDNS() {
        tabelaDNS = new HashMap<String, String>();
        clientesConectados = new HashSet<InetSocketAddress>();

        for (int i = 0; i < 10; i++) {
            String nome = "servidor" + (i + 1);
            String enderecoIP = "192.168.0." + (i + 1);
            tabelaDNS.put(nome, enderecoIP);
        }

        rodar();
    }

    private void rodar() {
        try {
            socket = new DatagramSocket(PORTA_DNS);
            host = InetAddress.getLocalHost();

            System.out.println("Servidor DNS rodando em: " + host.getHostAddress() + ":" + PORTA_DNS + "...");
            
            while (true){
                byte[] buffer = new byte[2048];
                DatagramPacket pacoteRecebido = new DatagramPacket(buffer, buffer.length);

                // aguarda mensagem do cliente
                socket.receive(pacoteRecebido);

                String mensagemRecebida = new String(buffer, 0, pacoteRecebido.getLength(), StandardCharsets.UTF_8);

                // se houve mensagem do cliente
                if (!mensagemRecebida.isEmpty()){
                    
                    // [CRIPTO] decriptografia aqui
                    
                    System.out.println("Mensagem recebida: " + mensagemRecebida);

                    String resposta = "";

                    // mensagem inicial para registrar cliente conectado
                    if (mensagemRecebida.startsWith("HELLO")){
                        System.out.println("Novo cliente: " + mensagemRecebida);
                        InetSocketAddress novoCliente = new InetSocketAddress(pacoteRecebido.getAddress(), pacoteRecebido.getPort());
                        clientesConectados.add(novoCliente);
                        continue; // não precisa enviar resposta para o cliente nesse caso
                    }

                    // opções de operações solicitadas pelo cliente
                    else if (mensagemRecebida.startsWith("LIST")){
                        resposta = "Servidores:\n";

                        for (HashMap.Entry<String, String> entry : tabelaDNS.entrySet()){
                            resposta += entry.getKey() + " -> " + entry.getValue() + "\n";
                        }
                        resposta += "\n";

                        //TODO jogar esse print pra depois do write
                        System.out.println("Listagem enviada ao cliente.");
                    }
                    else if (mensagemRecebida.startsWith("GET|")){
                        String nomeServidor = mensagemRecebida.substring(4).trim();
                        String enderecoIP = tabelaDNS.get(nomeServidor);

                        if (enderecoIP != null) resposta = "Endereço IP de " + nomeServidor + ": " + enderecoIP;
                        else resposta = nomeServidor + " não encontrado.";

                        //TODO jogar esse print pra depois do write
                        System.out.println("Endereço de servidor enviado ao cliente.");
                    }

                    else if (mensagemRecebida.startsWith("SET|")){
                        String[] partes = mensagemRecebida.split("\\|");
                        if (partes.length == 3){
                            String nomeServidorSet = partes[1].trim();
                            String novoEnderecoIP = partes[2].trim();

                            String ipAntigo = tabelaDNS.get(nomeServidorSet);

                            if (ipAntigo == null) {
                                //caso onde a resposta precisa ser enviada antes do loop reiniciar
                                resposta = "Servidor " + nomeServidorSet + " não encontrado."; 
                                
                                // [CRIPTO] criptografia aqui

                                byte[] dados = resposta.getBytes(StandardCharsets.UTF_8);
                                DatagramPacket pacoteResposta = new DatagramPacket(dados, dados.length, pacoteRecebido.getAddress(), pacoteRecebido.getPort());
                                socket.send(pacoteResposta);
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

                    else if (mensagemRecebida.startsWith("QUIT")){
                        resposta = "NOTIFY|Desconectando do servidor...\n";
                        InetSocketAddress cliente = new InetSocketAddress(pacoteRecebido.getAddress(), pacoteRecebido.getPort());
                        clientesConectados.remove(cliente);
                        
                        //TODO criar um print dessa operação pra depois do write
                        System.out.println("O cliente " + cliente.toString() + " desconectou.");
                    }
                    
                    else {
                        resposta = "Operação inválida.";
                    }

                    // [CRIPTO] criptografia aqui
                    
                    //TODO criar um seletor de prints pós write
                    byte[] dados = resposta.getBytes(StandardCharsets.UTF_8);
                    DatagramPacket pacoteResposta = new DatagramPacket(dados, dados.length, pacoteRecebido.getAddress(), pacoteRecebido.getPort());
                    socket.send(pacoteResposta);
                } 
            }
        } catch (IOException e){
            System.err.println("Erro no servidor: " + e.getMessage());
        } finally {
            if (!socket.isClosed()) {
                socket.close();
            }
        }
    }

    private void notificarClientes(String nomeServidor, String ipAntigo, String novoEnderecoIP){
        String notificacao = "NOTIFY|ALTERACAO DE IP|" + nomeServidor + "|" + ipAntigo + "->" + novoEnderecoIP;
        // Enviar notificação para todos os clientes conectados
        for (InetSocketAddress destino : clientesConectados){
            try {
                // [CRIPTO] criptografia aqui

                byte[] dados = notificacao.getBytes(StandardCharsets.UTF_8);
                DatagramPacket pacoteNotificacao = new DatagramPacket(dados, dados.length, destino.getAddress(), destino.getPort());
                socket.send(pacoteNotificacao);
            } catch (IOException e) {
                System.err.println("Erro ao notificar cliente: " + e.getMessage());
            }
        }
    }

    public static void main(String[] args){
        new ServidorDNS();
    }
}
