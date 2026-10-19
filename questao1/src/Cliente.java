import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class Cliente {
    private boolean isRegistrador;
    DatagramSocket socket = null;
    private final int PORTA_DNS = 5959;
    
    public Cliente(boolean isRegistrador) {
        this.isRegistrador = isRegistrador;
        rodar();
    }

    private void rodar(){
        try {
            // supondo que o cliente já conhece o endereço IP e a porta do DNS
            socket = new DatagramSocket();
            InetAddress enderecoServidor = InetAddress.getByName("localhost");

            // envio inicial para estabelecimento de informações de conexão cliente-servidor
            String mensagemInicial = "HELLO de " + socket.getInetAddress() + ":" + socket.getLocalPort();
            byte[] hello = mensagemInicial.getBytes(StandardCharsets.UTF_8);
            DatagramPacket pacoteHello = new DatagramPacket(hello, hello.length, enderecoServidor, PORTA_DNS);
            socket.send(pacoteHello);

            // thread para ouvir mensagens do servidor
            new Thread (new Runnable(){
                @Override
                public void run(){
                    try {
                        while (true){
                            byte[] buffer = new byte[2048];
                            DatagramPacket pacoteRecebido = new DatagramPacket(buffer, buffer.length);
                            socket.receive(pacoteRecebido);
                            // por algum motivo não precisa de buffer = pacoteRecebido.getData()
                            
                            String mensagemRecebida = new String(buffer, 0, pacoteRecebido.getLength(), StandardCharsets.UTF_8);
                            if (!mensagemRecebida.isEmpty()){

                                // [CRIPTO] decriptografia aqui


                                if (mensagemRecebida.startsWith("NOTIFY|")){
                                    System.out.println("\n[NOTIFICAÇÃO]: " + mensagemRecebida.substring(7) + "\n");
                                }
                                else{
                                    System.out.println("Resposta do servidor:\n" + mensagemRecebida);
                                }
                                
                            }
                        }
                    } catch (IOException e) {
                        if (!socket.isClosed()){
                            System.err.println("Erro ao escutar servidor: " + e.getMessage());
                        }
                        
                    }
                }
            }).start();

            @SuppressWarnings("resource")
            Scanner teclado = new Scanner(System.in);

            // loop para enviar mensagens ao servidor
            while (true){
                menu();

                if (!teclado.hasNextLine()){
                    return;
                }
                String operacao = teclado.nextLine();
                String resposta = "";

                switch(operacao){
                    case "0":
                        resposta = "LIST";
                        break;
                    case "1":
                        System.out.println("Qual o servidor?");
                        String nomeServidor = teclado.nextLine();

                        resposta = "GET|" + nomeServidor;
                        break;
                    
                    // exige cliente registrador;
                    case "2":
                        if (!isRegistrador){
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
                        // caso onde a resposta precisa ser enviada antes do cliente sair
                        resposta = "QUIT";

                        // [CRIPTO] criptografia aqui

                        byte[] dados = resposta.getBytes(StandardCharsets.UTF_8);
                        DatagramPacket pacoteResposta = new DatagramPacket(dados, dados.length, enderecoServidor, PORTA_DNS);
                        socket.send(pacoteResposta);
                        socket.close();
                        return;

                    default:
                        System.out.println("[ERROR] Operação inválida. Tente novamente.");
                        operacao = null;
                        break;
                }
                
                if (operacao == null) continue;

                // [CRIPTO] criptografia aqui

                byte[] dados = resposta.getBytes(StandardCharsets.UTF_8);
                DatagramPacket pacoteResposta = new DatagramPacket(dados, dados.length, enderecoServidor, PORTA_DNS);
                socket.send(pacoteResposta);
            }

        } catch (IOException e) {
            System.err.println("Erro ao se comunicar com servidor: " + e.getMessage());
        } finally {
            if (!socket.isClosed()) {
                socket.close();
            }
        }
    }

    private void menu(){
        System.out.println("OPERAÇÕES DO MINI DNS:");
        System.out.println(
        "0 - LIST (listar servidores registrados no DNS)\n" +
        "1 - GET (obter endereço de servidor por nome)\n" +
        "2 - SET (definir endereço de servidor por nome)\n" +
        "3 - QUIT (encerrar conexão)"
        );
        System.out.println("Selecione uma operação: ");
    }

    public static void main(String[] args){
        new Cliente(true);
        //new Cliente(false);
    }
}
