import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;

public class ServidorBorda {
    final private int PORTA_BORDA = 8003;
    final private int PORTA_INVALIDACAO = 8103;
    final private int PORTA_ORIGEM = 8000;
    private static final long TTL_NANOS = java.util.concurrent.TimeUnit.SECONDS.toNanos(10); // 10 segundos de TTL

    private static class EntradaCache {
        final String arquivo;
        final long criadaEm = System.nanoTime();

        EntradaCache(String arquivo) {
            this.arquivo = arquivo;
        }
    }

    private ConcurrentHashMap<String, EntradaCache> cache; // compartilhado com o listener de invalidações

    public ServidorBorda(){
        cache = new ConcurrentHashMap<>();
        rodar();
    }

    private void rodar(){
        ServerSocket servidorBorda = null;
        try {
            servidorBorda = new ServerSocket(PORTA_BORDA);

            System.out.println("Servidor de borda rodando na porta " + PORTA_BORDA + "...");

            new Thread(new Runnable() {
                @Override
                public void run() {
                    ouvirInvalidacoes();
                }
            }).start();

            // busca novas conexões
            while (true){
                Socket cliente = servidorBorda.accept();

                try {
                    System.out.println("Cliente conectado: " + cliente.getInetAddress().getHostAddress());
                    
                    // como cliente só manda uma solicitação por vez, não precisa de thread nem laço 
                    InputStream entrada = cliente.getInputStream();
                    OutputStream saida = cliente.getOutputStream();

                    // recebe mensagens de um cliente
                    byte[] buffer = new byte[4096];
                    int bytesLidos = entrada.read(buffer);

                    if (bytesLidos == -1){
                        System.out.println("Cliente desconectado: " + cliente.getInetAddress().getHostAddress());
                        continue;
                    }

                    if (bytesLidos > 0){
                        String mensagemRecebida = new String(buffer, 0, bytesLidos, "UTF-8");
                        if (!mensagemRecebida.startsWith("GET /")){
                            System.out.println("Mensagem inválida recebida: " + mensagemRecebida);
                            saida.write("[ERROR] Mensagem inválida\n".getBytes(StandardCharsets.UTF_8));
                            continue;
                        }
                        
                        System.out.println("Mensagem recebida do cliente: " + mensagemRecebida);

                        String nomeArquivo = mensagemRecebida.substring(5); // remove GET /
                        String regraNomeArquivo = "arquivo(?:[1-9]\\d{0,2}|1000)\\.ext"; // arquivo1.ext até arquivo1000.ext, sem 0 à esquerda 

                        if (!nomeArquivo.matches(regraNomeArquivo)){
                            System.out.println("Nome de arquivo inválido recebido: " + nomeArquivo);
                            saida.write("[ERROR] Nome de arquivo inválido\n".getBytes(StandardCharsets.UTF_8));
                            continue;
                        }
                        String idArquivo = nomeArquivo.substring(7, nomeArquivo.length() - 4); // remove "arquivo" e ".ext"

                        // verifica cache hit ou miss
                        buscarNaCache(idArquivo, saida);
                    }
                } catch (Exception e){
                    System.out.println("Erro na conexão com o cliente: " + e.getMessage());
                } finally {
                    // fecha a conexão com o cliente
                    try {
                        cliente.close();
                    } catch (Exception e){
                        System.out.println("Erro ao fechar conexão com o cliente: " + e.getMessage());
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("Erro ao iniciar o servidor de borda: " + e.getMessage());
        } finally {
            if (servidorBorda != null){
                try {
                    servidorBorda.close();
                } catch (Exception e) {
                    System.out.println("Erro ao fechar o servidor de borda: " + e.getMessage());
                }
            }
        }
    }

    // Origem inicia uma conexão TCP e envia uma linha: INVALIDATE /arquivoN.ext
    private void ouvirInvalidacoes() {
        ServerSocket servidorInvalidacao = null;
        try {
            servidorInvalidacao = new ServerSocket(PORTA_INVALIDACAO);
            System.out.println("Borda escutando invalidações na porta " + PORTA_INVALIDACAO + "...");
            while (true) {
                Socket origem = servidorInvalidacao.accept();
                try {
                    InputStream entrada = origem.getInputStream();
                    OutputStream saida = origem.getOutputStream();

                    byte[] buffer = new byte[4096];
                    int bytesLidos = entrada.read(buffer);
                    // se bytesLidos == -1, a conexão foi fechada pelo cliente, então tratamos como uma string vazia
                    // se não, lemos a string normalment
                    String comando = bytesLidos == -1 ? "" : new String(buffer, 0, bytesLidos, StandardCharsets.UTF_8);

                    if (!comando.startsWith("INVALIDATE /")) {
                        saida.write("[ERROR] Comando de invalidação inválido\n".getBytes(StandardCharsets.UTF_8));
                        continue;
                    }
                    String nomeArquivo = comando.substring("INVALIDATE /".length());
                    if (!nomeArquivo.matches("arquivo(?:[1-9]\\d{0,2}|1000)\\.ext")) {
                        saida.write("[ERROR] Nome de arquivo inválido\n".getBytes(StandardCharsets.UTF_8));
                        continue;
                    }

                    String idArquivo = nomeArquivo.substring(7, nomeArquivo.length() - 4);
                    cache.remove(idArquivo);
                    System.out.println("Cache invalidado: " + nomeArquivo);
                    saida.write(("INVALIDATED /" + nomeArquivo + "\n").getBytes(StandardCharsets.UTF_8));
                } catch (IOException e) {
                    System.out.println("Erro ao receber invalidação: " + e.getMessage());
                } finally {
                    try {
                        origem.close();
                    } catch (IOException e) {
                        System.out.println("Erro ao fechar conexão de invalidação: " + e.getMessage());
                    }
                }
            }
        } catch (IOException e) {
            System.out.println("Erro no listener de invalidações: " + e.getMessage());
        } finally {
            if (servidorInvalidacao != null) {
                try {
                    servidorInvalidacao.close();
                } catch (IOException e) {
                    System.out.println("Erro ao fechar listener de invalidações: " + e.getMessage());
                }
            }
        }
    }

    private void buscarNaCache(String idArquivo, OutputStream saida) throws IOException{
        EntradaCache entrada = cache.get(idArquivo);
        if (entrada != null && System.nanoTime() - entrada.criadaEm >= TTL_NANOS) { // não é nulo e TTL expirou
            cache.remove(idArquivo);
            entrada = null;
            System.out.println("TTL expirado: arquivo" + idArquivo + ".ext");
        }

        if (entrada != null){
            System.out.println("Cache HIT!");
            saida.write(("HIT /" + entrada.arquivo + "\n").getBytes(StandardCharsets.UTF_8));
        } else {
            String nomeArquivo = "arquivo" + idArquivo + ".ext";
            System.out.println("MISS para o arquivo: " + nomeArquivo);
            saida.write(("MISS /" + nomeArquivo + "\n").getBytes(StandardCharsets.UTF_8));
            buscarNaOrigem(idArquivo, saida);
        }
    }

    private void buscarNaOrigem(String idArquivo, OutputStream saida) throws UnknownHostException, IOException{
        Socket servidorOrigem = null;
        try {
            servidorOrigem = new Socket("localhost", PORTA_ORIGEM);
            // socket TCP para comunicação com origem

            OutputStream saidaOrigem = servidorOrigem.getOutputStream();
            InputStream entradaOrigem = servidorOrigem.getInputStream();

            String mensagemParaOrigem = "GET /arquivo" + idArquivo + ".ext";
            saidaOrigem.write(mensagemParaOrigem.getBytes("UTF-8"));

            // recebe a resposta do servidor de origem
            byte[] bufferOrigem = new byte[4096];
            int bytesLidosOrigem = entradaOrigem.read(bufferOrigem);

            if (bytesLidosOrigem > 0){
                String respostaOrigem = new String(bufferOrigem, 0, bytesLidosOrigem, StandardCharsets.UTF_8).trim();
                if (!respostaOrigem.equals("DATA /arquivo" + idArquivo + ".ext")) {
                    String erro = respostaOrigem.startsWith("[ERROR]") ? respostaOrigem : "[ERROR] Resposta inválida da origem";
                    saida.write((erro + "\n").getBytes(StandardCharsets.UTF_8));
                    return;
                }

                cache.put(idArquivo, new EntradaCache("arquivo" + idArquivo + ".ext"));
                saida.write((respostaOrigem + "\n").getBytes(StandardCharsets.UTF_8));
            }
        } catch (IOException e) {
            System.out.println("Erro ao buscar na origem: " + e.getMessage());
            saida.write("[ERROR] Servidor de Origem inacessível\n".getBytes(StandardCharsets.UTF_8));
        } finally {
            // fecha a conexão com o servidor de origem
            try {
                if (servidorOrigem != null) {
                    servidorOrigem.close();
                }
            } catch (Exception e) {
                System.out.println("Erro ao fechar conexão com o servidor de origem: " + e.getMessage());
            }
        }

    }

    public static void main(String[] args) {
        new ServidorBorda();
    }
}
