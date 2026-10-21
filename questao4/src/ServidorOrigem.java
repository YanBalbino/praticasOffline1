import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;

public class ServidorOrigem {
    private final int PORTA_ORIGEM = 8000;
    private HashMap<String,String> arquivos; // hashmap para agilizar buscas, não usei Set por falta de familiaridade 

    public ServidorOrigem(){
        arquivos = new HashMap<>();

        for (int i = 1; i <= 1000; i++){
            arquivos.put(i + "", "arquivo" + i + ".ext"); // par chave valor {id, arquivo[id].ext}
        }

        rodar();
    }

    private void rodar(){
        ServerSocket servidorOrigem = null;
        try {
            servidorOrigem = new ServerSocket(PORTA_ORIGEM);

            System.out.println("Servidor de origem rodando na porta " + PORTA_ORIGEM + "...");

            // busca novas conexões
            while (true){
                Socket servidorBorda = servidorOrigem.accept();

                try {
                    System.out.println("Servidor de borda conectado: " + servidorBorda.getInetAddress().getHostAddress());
                    
                    // como Edge só manda uma solicitação por vez, não precisa de thread nem laço 
                    InputStream entrada = servidorBorda.getInputStream();
                    OutputStream saida = servidorBorda.getOutputStream();

                    // recebe mensagens de um cliente
                    byte[] buffer = new byte[4096];
                    int bytesLidos = entrada.read(buffer);

                    if (bytesLidos == -1){
                        System.out.println("Servidor de borda desconectado: " + servidorBorda.getInetAddress().getHostAddress());
                        continue;
                    }

                    if (bytesLidos > 0){
                        String mensagemRecebida = new String(buffer, 0, bytesLidos, "UTF-8");
                        if (!mensagemRecebida.startsWith("GET /")){
                            System.out.println("Mensagem inválida recebida: " + mensagemRecebida);
                            saida.write("Mensagem inválida".getBytes("UTF-8"));
                            continue;
                        }
                        
                        System.out.println("Mensagem recebida da borda: " + mensagemRecebida);

                        String nomeArquivo = mensagemRecebida.substring(5); // remove GET /
                        if (!nomeArquivo.matches("arquivo\\d+\\.ext") || nomeArquivo.length() > 15){
                            System.out.println("Arquivo inválido solicitado: " + nomeArquivo);
                            saida.write("Arquivo inválido".getBytes("UTF-8"));
                            continue;
                        }

                        String idArquivo = nomeArquivo.substring(7, nomeArquivo.length() - 4); // remove "arquivo" e ".ext"

                        if (!arquivos.containsKey(idArquivo)){
                            System.out.println("Arquivo não encontrado: " + nomeArquivo);
                            saida.write("Arquivo não encontrado".getBytes("UTF-8"));
                            continue;
                        }
                        // envia resposta para o cliente
                        String resposta = "Conteúdo do arquivo " + arquivos.get(idArquivo);
                        saida.write(resposta.getBytes("UTF-8"));
                    }
                } catch (IOException e){
                    System.out.println("Erro na conexão com o servidor de borda: " + e.getMessage());
                } finally {
                    // fecha a conexão com o cliente
                    try {
                        servidorBorda.close();
                    } catch (IOException e){
                        System.out.println("Erro ao fechar conexão com o servidor de borda: " + e.getMessage());
                    }
                }
            }

        } catch (IOException e){
            System.out.println("Erro na conexão: " + e.getMessage());
        } finally {
            // fecha o servidor
            if (servidorOrigem != null){
                try {
                    servidorOrigem.close();
                } catch (IOException e){
                    System.out.println("Erro ao fechar o servidor: " + e.getMessage());
                }
            }
        }
    }

    public static void main(String[] args){
        new ServidorOrigem();
    }
}
