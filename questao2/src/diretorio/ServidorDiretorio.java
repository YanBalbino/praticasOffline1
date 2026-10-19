package diretorio;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.SecretKey;

import log.Color;
import model.InfoServidor;
import seguranca.CriptoUtils;
import seguranca.EnvelopeCriptografico;

public class ServidorDiretorio {
    public static final int PORTA_DIRETORIO = 6000;
    private static Map<String, InfoServidor> servidoresRegistrados;
    private static AtomicInteger indiceRodizio;

    private final KeyPair parChavesRSA;
    private final SecretKey chaveAES;
    private final SecretKey chaveHMAC;
    private ServerSocket serverSocket;
    private volatile boolean executando = true;

    public ServidorDiretorio() {
        this(false);
    }

    public ServidorDiretorio(boolean modoAssincrono) {
        servidoresRegistrados = new ConcurrentHashMap<String, InfoServidor>();
        indiceRodizio = new AtomicInteger(0);
        this.parChavesRSA = CriptoUtils.gerarParChavesRSA();
        this.chaveAES = CriptoUtils.gerarChaveAES();
        this.chaveHMAC = CriptoUtils.gerarChaveHMAC();

        if (modoAssincrono) {
            new Thread(this::rodar, "Thread-ServidorDiretorio").start();
        } else {
            rodar();
        }
    }

    private void rodar() {
        try {
            serverSocket = new ServerSocket(PORTA_DIRETORIO);
            Color.info("[Diretório] Servidor de Diretório seguro (RSA+AES+HMAC) rodando na porta " + PORTA_DIRETORIO + "...");

            while (executando) {
                Socket conexao = serverSocket.accept();
                new Thread(() -> atenderConexao(conexao)).start();
            }
        } catch (IOException e) {
            if (executando) {
                Color.erro("[Diretório] Erro no Servidor de Diretório: " + e.getMessage());
            }
        } finally {
            fechar();
        }
    }

    private void atenderConexao(Socket conexao) {
        try (
                BufferedReader leitor = new BufferedReader(
                        new InputStreamReader(conexao.getInputStream(), StandardCharsets.UTF_8));
                PrintWriter escritor = new PrintWriter(
                        new OutputStreamWriter(conexao.getOutputStream(), StandardCharsets.UTF_8), true)
        ) {
            String linhaRecebida;
            while ((linhaRecebida = leitor.readLine()) != null) {
                linhaRecebida = linhaRecebida.trim();
                if (linhaRecebida.isEmpty()) {
                    continue;
                }

                String msgRecebida;
                try {
                    EnvelopeCriptografico envelope = EnvelopeCriptografico.abrirEValidarEnvelope(
                            linhaRecebida,
                            "ServidorDiretorio"
                    );
                    msgRecebida = envelope.getMensagemOriginal().trim();
                    Color.info("[Diretório] Mensagem autenticada e decifrada de '"
                            + envelope.getNomeEmissor() + "': " + msgRecebida);
                } catch (SecurityException se) {
                    Color.erro("[Diretório - ALERTA DE SEGURANÇA] Pacote rejeitado! " + se.getMessage());
                    enviarEnvelopeSeguro(escritor, "ERRO_HMAC|Execução rejeitada pelo Diretório: Falha de integridade/autenticidade no HMAC!");
                    continue;
                }

                // REGISTER|nome|ip|porta|SOMA,SUBTRACAO,MULTIPLICACAO,DIVISAO
                if (msgRecebida.startsWith("REGISTER|")) {
                    String[] partes = msgRecebida.split("\\|");
                    if (partes.length == 5) {
                        String nome = partes[1].trim();
                        String ip = partes[2].trim();
                        int porta = Integer.parseInt(partes[3].trim());
                        List<String> servicos = Arrays.asList(partes[4].trim().split(","));

                        InfoServidor info = new InfoServidor(nome, ip, porta, servicos, true);
                        servidoresRegistrados.put(nome, info);

                        String resposta = "OK|Servidor " + nome + " (" + ip + ":" + porta + ") registrado com canal seguro!";
                        enviarEnvelopeSeguro(escritor, resposta);
                        Color.sucesso("[Diretório] " + resposta);
                    } else {
                        enviarEnvelopeSeguro(escritor, "ERRO|Formato inválido para REGISTER.");
                    }
                }

                else if (msgRecebida.startsWith("LIST")) {
                    StringBuilder resposta = new StringBuilder("Servidores registrados no Diretório:\n");
                    if (servidoresRegistrados.isEmpty()) {
                        resposta.append("Nenhum servidor registrado no momento.");
                    } else {
                        List<InfoServidor> ordenados = new ArrayList<InfoServidor>(servidoresRegistrados.values());
                        Collections.sort(ordenados, Comparator.comparing(InfoServidor::getNome));
                        for (InfoServidor info : ordenados) {
                            boolean online = verificarServidorOnline("localhost", info.getPorta());
                            if (!online) {
                                info.setAtivo(false);
                            }
                            resposta.append(" - ").append(info.toString()).append("\n");
                        }
                    }
                    enviarEnvelopeSeguro(escritor, resposta.toString().trim());
                }

                // DISCOVER|OPERACAO (ex: DISCOVER|Calcular soma ou DISCOVER|SOMA)
                else if (msgRecebida.startsWith("DISCOVER|")) {
                    String operacaoSolicitada = msgRecebida.substring(9).trim();

                    // Caso 3: Validação de entrada na consulta (ex: "Calcular modulo" não cadastrada)
                    if (!InfoServidor.isOperacaoValida(operacaoSolicitada)) {
                        Color.erro("[Diretório] Consulta com serviço inválido ('" + operacaoSolicitada
                                + "') -> Erro na entrada de dados. Tente outra vez!");
                        enviarEnvelopeSeguro(escritor, "ERRO_ENTRADA|Erro na entrada de dados. Tente outra vez!");
                        continue;
                    }

                    String operacaoNormalizada = InfoServidor.normalizarOperacao(operacaoSolicitada);
                    List<InfoServidor> ativos = listarServidoresAtivosParaServico(operacaoNormalizada);

                    if (!ativos.isEmpty()) {
                        // Balanceamento de carga Round-Robin entre os servidores ativos
                        int idx = Math.abs(indiceRodizio.getAndIncrement() % ativos.size());
                        InfoServidor servidorSelecionado = ativos.get(idx);

                        StringBuilder listaAtivosStr = new StringBuilder();
                        for (int i = 0; i < ativos.size(); i++) {
                            if (i > 0) {
                                listaAtivosStr.append(", ");
                            }
                            listaAtivosStr.append(ativos.get(i).getResumoEndereco());
                        }

                        // OK|nomeSelecionado|ipSelecionado|portaSelecionada|listaServidoresAtivos
                        String resposta = "OK|" + servidorSelecionado.getNome() + "|"
                                + servidorSelecionado.getendereco() + "|"
                                + servidorSelecionado.getPorta() + "|"
                                + listaAtivosStr.toString();

                        enviarEnvelopeSeguro(escritor, resposta);
                        Color.sucesso("[Diretório] Serviço '" + operacaoSolicitada + "' -> Ativos: ["
                                + listaAtivosStr + "] | Balanceador (Round-Robin) selecionou: "
                                + servidorSelecionado.getNome() + " (" + servidorSelecionado.getendereco() + ":"
                                + servidorSelecionado.getPorta() + ")");
                    } else {
                        String resposta = "ERRO|Nenhum servidor ATIVO encontrado para o serviço: " + operacaoSolicitada;
                        enviarEnvelopeSeguro(escritor, resposta);
                    }
                }

                else if (msgRecebida.startsWith("STATUS|")) {
                    String[] partes = msgRecebida.split("\\|");
                    if (partes.length == 3) {
                        String nomeServidor = partes[1].trim();
                        String novoStatus = partes[2].trim().toUpperCase();

                        InfoServidor info = servidoresRegistrados.get(nomeServidor);
                        if (info == null) {
                            enviarEnvelopeSeguro(escritor, "ERRO|Servidor " + nomeServidor + " não encontrado no diretório.");
                        } else {
                            boolean ativo = novoStatus.equals("ATIVO");
                            info.setAtivo(ativo);
                            String resposta = "Status de " + nomeServidor + " alterado para: " + (ativo ? "ATIVO" : "INATIVO");
                            enviarEnvelopeSeguro(escritor, resposta);
                            Color.info("[Diretório] " + resposta);
                        }
                    } else {
                        enviarEnvelopeSeguro(escritor, "ERRO_ENTRADA|Erro na entrada de dados. Tente outra vez!");
                    }
                }

                else if (msgRecebida.startsWith("QUIT")) {
                    Color.info("[Diretório] Cliente desconectou: " + conexao.getInetAddress());
                    break;
                }

                else {
                    enviarEnvelopeSeguro(escritor, "ERRO_ENTRADA|Erro na entrada de dados. Tente outra vez!");
                }
            }
        } catch (IOException e) {
            Color.erro("[Diretório] Erro na comunicação com cliente/servidor: " + e.getMessage());
        } finally {
            try {
                conexao.close();
            } catch (IOException e) {
                // Ignora erro ao fechar socket
            }
        }
    }

    private void enviarEnvelopeSeguro(PrintWriter escritor, String mensagemPlano) {
        String envelope = EnvelopeCriptografico.criarEnvelope(
                mensagemPlano,
                chaveAES,
                chaveHMAC,
                parChavesRSA,
                "ServidorDiretorio"
        );
        escritor.println(envelope);
    }

    // Procura todos os servidores ativos que oferecem a operação solicitada (ordenados por nome para Round-Robin determinístico)
    private List<InfoServidor> listarServidoresAtivosParaServico(String operacao) {
        List<InfoServidor> candidatosAtivos = new ArrayList<InfoServidor>();

        List<InfoServidor> todos = new ArrayList<InfoServidor>(servidoresRegistrados.values());
        Collections.sort(todos, Comparator.comparing(InfoServidor::getNome));

        for (InfoServidor info : todos) {
            if (info.isAtivo() && info.ofereceServico(operacao)) {
                if (verificarServidorOnline("localhost", info.getPorta())) {
                    candidatosAtivos.add(info);
                } else {
                    info.setAtivo(false);
                }
            }
        }

        return candidatosAtivos;
    }

    public void resetarIndiceRodizio() {
        indiceRodizio.set(0);
    }

    private boolean verificarServidorOnline(String host, int porta) {
        try (Socket s = new Socket(host, porta);
             PrintWriter out = new PrintWriter(new OutputStreamWriter(s.getOutputStream(), StandardCharsets.UTF_8), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8))) {
            s.setSoTimeout(1500);
            out.println("PING");
            String resp = in.readLine();
            return "PONG".equals(resp);
        } catch (IOException e) {
            return false;
        }
    }

    public void fechar() {
        executando = false;
        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                // Ignora erro no fechamento
            }
        }
    }

    public static void main(String[] args) {
        new ServidorDiretorio(false);
    }
}
