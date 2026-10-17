import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Scanner;

public class Cliente {
    private String host;
    private int porta;
    private boolean isRegistrador;
    
    public Cliente(String host, int porta, boolean isRegistrador) {
        this.host = host;
        this.porta = porta;
        this.isRegistrador = isRegistrador;
        rodar();
    }

    private void rodar(){
        Socket socket = null;

        try {
            // supondo que o cliente já conhece o endereço IP e a porta do DNS
            socket = new Socket(host, porta);
            System.out.println("Conectado ao servidor!");

            OutputStream saida = socket.getOutputStream();
            InputStream entrada = socket.getInputStream();

            // thread para ouvir mensagens do servidor
            new Thread (new Runnable(){
                @Override
                public void run(){
                    try {
                        while (true){
                            byte[] buffer = new byte[512];
                            int bytesLidos = entrada.read(buffer);
                            if (bytesLidos > 0){
                                String resposta = new String(buffer, 0, bytesLidos, "UTF-8");

                                if (resposta.startsWith("NOTIFY|")){
                                    System.out.println("\n[NOTIFICAÇÃO]: " + resposta.substring(7) + "\n");
                                }
                                else{
                                    System.out.println("Resposta do servidor:\n" + resposta);
                                }
                                
                            }

                            else if (bytesLidos == -1){
                                System.out.println("Servidor fechou a conexão.");
                                break;
                            }
                        }
                    } catch (IOException e) {
                        System.err.println("Erro ao escutar servidor: " + e.getMessage());
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

                switch(operacao){
                    case "0":
                        saida.write("LIST".getBytes("UTF-8"));
                        break;
                    case "1":
                        System.out.println("Qual o servidor?");
                        String nomeServidor = teclado.nextLine();
                        saida.write(("GET|" + nomeServidor).getBytes("UTF-8"));
                        break;
                    
                    // envolve cliente registrador;
                    case "2":
                        if (!isRegistrador){
                            System.out.println("Operação inválida. Apenas clientes registradores podem definir endereços IP.\n");
                            operacao = null;
                            break;
                        }
                        System.out.println("Qual o servidor?");
                        String nomeServidorSet = teclado.nextLine();
                        System.out.println("Qual o novo endereço IP?");
                        String enderecoIP = teclado.nextLine();
                        saida.write(("SET|" + nomeServidorSet + "|" + enderecoIP).getBytes("UTF-8"));
                        break;
                    case "3":
                        saida.write("QUIT".getBytes("UTF-8"));
                        System.out.println("Desconectando do servidor...");
                        socket.close();
                        return;

                    default:
                        System.out.println("Operação inválida. Tente novamente.");
                        operacao = null;
                        break;
                }
                
                if (operacao == null) continue;
            }

        } catch (IOException e) {
            System.err.println("Erro ao se comunicar com servidor: " + e.getMessage());
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    System.err.println("Erro ao fechar o socket: " + e.getMessage());
                }
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
        //new Cliente("localhost", 5353, true);
        new Cliente("localhost", 5353, false);
    }
}
