import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Scanner;

public class ServidorOrigem {
    private final int PORTA_ORIGEM = 8000;
    private final int PORTA_INVALIDACAO_BORDA = 8103;
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

            new Thread(new Runnable() {
                @Override
                public void run() {
                    Scanner teclado = new Scanner(System.in);
                    while (true) {
                        System.out.println("1 - Invalidar arquivo na borda | 0 - Sair do menu");
                        if (!teclado.hasNextLine()) return;
                        String opcao = teclado.nextLine().trim();
                        if ("0".equals(opcao)) return;
                        if (!"1".equals(opcao)) {
                            System.out.println("Opção inválida.");
                            continue;
                        }

                        System.out.println("Nome do arquivo:");
                        if (!teclado.hasNextLine()) return;
                        String nomeArquivo = teclado.nextLine().trim();
                        if (!nomeArquivo.matches("arquivo(?:[1-9]\\d{0,2}|1000)\\.ext")) {
                            System.out.println("[ERROR] Nome de arquivo inválido");
                            continue;
                        }
                        invalidarCache(nomeArquivo);
                    }
                }
            }).start();

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
                            saida.write("[ERROR] Mensagem inválida\n".getBytes(StandardCharsets.UTF_8));
                            continue;
                        }
                        
                        System.out.println("Mensagem recebida da borda: " + mensagemRecebida);

                        String nomeArquivo = mensagemRecebida.substring(5); // remove GET /
                        if (!nomeArquivo.matches("arquivo(?:[1-9]\\d{0,2}|1000)\\.ext")){
                            System.out.println("Arquivo inválido solicitado: " + nomeArquivo);
                            saida.write("[ERROR] Arquivo inválido\n".getBytes(StandardCharsets.UTF_8));
                            continue;
                        }

                        String idArquivo = nomeArquivo.substring(7, nomeArquivo.length() - 4); // remove "arquivo" e ".ext"

                        if (!arquivos.containsKey(idArquivo)){
                            System.out.println("Arquivo não encontrado: " + nomeArquivo);
                            saida.write("[ERROR] Arquivo não encontrado\n".getBytes(StandardCharsets.UTF_8));
                            continue;
                        }
                        // envia resposta para o cliente
                        String resposta = "DATA /" + arquivos.get(idArquivo) + "\n";
                        saida.write(resposta.getBytes(StandardCharsets.UTF_8));
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

    private void invalidarCache(String nomeArquivo) {
        Socket borda = null;
        try {
            borda = new Socket("localhost", PORTA_INVALIDACAO_BORDA);

            OutputStream saida = borda.getOutputStream();
            InputStream entrada = borda.getInputStream();

            String comando = "INVALIDATE /" + nomeArquivo;
           saida.write(comando.getBytes(StandardCharsets.UTF_8));

            byte[] buffer = new byte[4096];
            int bytesLidos = entrada.read(buffer);

            String resposta = bytesLidos == -1 ? "" : new String(buffer, 0, bytesLidos, StandardCharsets.UTF_8).trim();

            if (("INVALIDATED /" + nomeArquivo).equals(resposta)) {
                System.out.println("Cache invalidado na borda: " + nomeArquivo);
            } else {
                System.out.println("[ERROR] Falha ao invalidar cache: " + resposta);
            }
        } catch (IOException e) {
            System.out.println("[ERROR] Falha na comunicação com a borda: " + e.getMessage());
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

    public static void main(String[] args){
        new ServidorOrigem();
    }
}
