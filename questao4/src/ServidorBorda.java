import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.HashMap;

public class ServidorBorda {
    final private int PORTA_BORDA = 8003;
    final private int PORTA_ORIGEM = 8000;
    private static final long TTL_NANOS = java.util.concurrent.TimeUnit.SECONDS.toNanos(10); // 10 segundos de TTL

    private static class EntradaCache {
        final String arquivo;
        final long criadaEm = System.nanoTime();

        EntradaCache(String arquivo) {
            this.arquivo = arquivo;
        }
    }

    private HashMap<String, EntradaCache> cache; // arquivos e instantes de entrada no cache

    public ServidorBorda(){
        cache = new HashMap<>();
        rodar();
    }

    private void rodar(){
        ServerSocket servidorBorda = null;
        try {
            servidorBorda = new ServerSocket(PORTA_BORDA);

            System.out.println("Servidor de borda rodando na porta " + PORTA_BORDA + "...");

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
                            saida.write("Mensagem inválida".getBytes("UTF-8"));
                            continue;
                        }
                        
                        System.out.println("Mensagem recebida do cliente: " + mensagemRecebida);

                        String nomeArquivo = mensagemRecebida.substring(5); // remove GET /
                        String regraNomeArquivo = "arquivo(?:[1-9]\\d{0,2}|1000)\\.ext"; // arquivo1.ext até arquivo1000.ext, sem 0 à esquerda 

                        if (!nomeArquivo.matches(regraNomeArquivo)){
                            System.out.println("Nome de arquivo inválido recebido: " + nomeArquivo);
                            saida.write("Nome de arquivo inválido".getBytes("UTF-8"));
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

    private void buscarNaCache(String idArquivo, OutputStream saida) throws IOException{
        EntradaCache entrada = cache.get(idArquivo);
        if (entrada != null && System.nanoTime() - entrada.criadaEm >= TTL_NANOS) { // não é nulo e TTL expirou
            cache.remove(idArquivo);
            entrada = null;
            System.out.println("TTL expirado: arquivo" + idArquivo + ".ext");
        }

        if (entrada != null){
            System.out.println("Cache HIT!");
            String resposta = "Arquivo em cache:" + entrada.arquivo;
            saida.write(resposta.getBytes("UTF-8"));
        } else {
            System.out.println("MISS para o arquivo: " + idArquivo);
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
                //TODO melhorar resposta
                String respostaOrigem = new String(bufferOrigem, 0, bytesLidosOrigem, "UTF-8");

                //TODO checar esse if após padronizar respostas
                if (respostaOrigem.startsWith("Arquivo não encontrado")){
                    System.out.println("Arquivo não encontrado na origem: " + idArquivo);
                    saida.write(respostaOrigem.getBytes("UTF-8"));
                    return;
                }

                // adiciona o arquivo à cache
                cache.put(idArquivo, new EntradaCache(respostaOrigem));

                // envia a resposta para o cliente
                saida.write(respostaOrigem.getBytes("UTF-8"));
            }
        } catch (IOException e) {
            System.out.println("Erro ao buscar na origem: " + e.getMessage());
            saida.write("[ERROR] Servidor de Origem inacessível".getBytes("UTF-8"));
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
