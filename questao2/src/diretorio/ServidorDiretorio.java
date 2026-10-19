package diretorio;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import model.InfoServidor;

public class ServidorDiretorio {
    public static final int PORTA_DIRETORIO = 6000;
    private static Map<String, InfoServidor> servidoresRegistrados;
    private static AtomicInteger indiceRodizio;

    public ServidorDiretorio() {
        servidoresRegistrados = new ConcurrentHashMap<String, InfoServidor>();
        indiceRodizio = new AtomicInteger(0);
        rodar();
    }

    private void rodar() {
        ServerSocket servidorDiretorio = null;

        try {
            servidorDiretorio = new ServerSocket(PORTA_DIRETORIO);
            System.out.println("Servidor de Diretório rodando na porta " + PORTA_DIRETORIO + "...");

            while (true) {
                Socket conexao = servidorDiretorio.accept();
                System.out.println("Nova conexão recebida: " + conexao.getInetAddress());

                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            InputStream entrada = conexao.getInputStream();
                            OutputStream saida = conexao.getOutputStream();

                            while (true) {
                                byte[] buffer = new byte[1024];
                                int bytesLidos = entrada.read(buffer);

                                if (bytesLidos == -1) {
                                    break;
                                }

                                if (bytesLidos > 0) {
                                    String msgRecebida = new String(buffer, 0, bytesLidos, "UTF-8").trim();
                                    System.out.println("[Diretório] Mensagem recebida: " + msgRecebida);

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

                                            String resposta = "OK|Servidor " + nome + " (" + ip + ":" + porta + ") registrado com sucesso!";
                                            saida.write(resposta.getBytes("UTF-8"));
                                            System.out.println("[Diretório] " + resposta);
                                        } else {
                                            saida.write("ERRO|Formato inválido para REGISTER.".getBytes("UTF-8"));
                                        }
                                    }

                                    else if (msgRecebida.startsWith("LIST")) {
                                        StringBuilder resposta = new StringBuilder("Servidores registrados no Diretório:\n");
                                        if (servidoresRegistrados.isEmpty()) {
                                            resposta.append("Nenhum servidor registrado no momento.\n");
                                        } else {
                                            for (InfoServidor info : servidoresRegistrados.values()) {
                                                boolean online = verificarServidorOnline("localhost", info.getPorta());
                                                if (!online) {
                                                    info.setAtivo(false);
                                                }
                                                resposta.append(" - ").append(info.toString()).append("\n");
                                            }
                                        }
                                        saida.write(resposta.toString().getBytes("UTF-8"));
                                    }

                                    // DISCOVER|OPERACAO
                                    else if (msgRecebida.startsWith("DISCOVER|")) {
                                        String operacao = msgRecebida.substring(9).trim();
                                        InfoServidor servidorAtivo = descobrirServidorAtivo(operacao);

                                        if (servidorAtivo != null) {
                                            String resposta = "OK|" + servidorAtivo.getNome() + "|"
                                                    + servidorAtivo.getendereco() + "|"
                                                    + servidorAtivo.getPorta();
                                            saida.write(resposta.getBytes("UTF-8"));
                                            System.out.println("[Diretório] Serviço '" + operacao + "' descoberto em: "
                                                    + servidorAtivo.getNome() + " (" + servidorAtivo.getendereco() + ")");
                                        } else {
                                            String resposta = "ERRO|Nenhum servidor ATIVO encontrado para o serviço: " + operacao;
                                            saida.write(resposta.getBytes("UTF-8"));
                                        }
                                    }

                                    else if (msgRecebida.startsWith("STATUS|")) {
                                        String[] partes = msgRecebida.split("\\|");
                                        if (partes.length == 3) {
                                            String nomeServidor = partes[1].trim();
                                            String novoStatus = partes[2].trim().toUpperCase();

                                            InfoServidor info = servidoresRegistrados.get(nomeServidor);
                                            if (info == null) {
                                                saida.write(("ERRO|Servidor " + nomeServidor + " não encontrado no diretório.").getBytes("UTF-8"));
                                            } else {
                                                boolean ativo = novoStatus.equals("ATIVO");
                                                info.setAtivo(ativo);
                                                String resposta = "Status de " + nomeServidor + " alterado para: " + (ativo ? "ATIVO" : "INATIVO");
                                                saida.write(resposta.getBytes("UTF-8"));
                                                System.out.println("[Diretório] " + resposta);
                                            }
                                        } else {
                                            saida.write("ERRO|Use: STATUS|nomeServidor|ATIVO ou INATIVO".getBytes("UTF-8"));
                                        }
                                    }

                                    else if (msgRecebida.startsWith("QUIT")) {
                                        System.out.println("Cliente desconectou: " + conexao.getInetAddress());
                                        conexao.close();
                                        break;
                                    }
                                }
                            }
                        } catch (IOException e) {
                            System.err.println("Erro na comunicação com cliente/servidor: " + e.getMessage());
                        } finally {
                            try {
                                conexao.close();
                            } catch (IOException e) {
                                System.err.println("Erro ao fechar socket: " + e.getMessage());
                            }
                        }
                    }
                }).start();
            }
        } catch (IOException e) {
            System.err.println("Erro no Servidor de Diretório: " + e.getMessage());
        } finally {
            if (servidorDiretorio != null) {
                try {
                    servidorDiretorio.close();
                } catch (IOException e) {
                    System.err.println("Erro ao fechar o Servidor de Diretório: " + e.getMessage());
                }
            }
        }
    }

    // Procura um servidor ativo que ofereça a operação solicitada
    private InfoServidor descobrirServidorAtivo(String operacao) {
        List<InfoServidor> candidatosAtivos = new ArrayList<InfoServidor>();

        for (InfoServidor info : servidoresRegistrados.values()) {
            if (info.isAtivo() && info.ofereceServico(operacao)) {
                if (verificarServidorOnline("localhost", info.getPorta())) {
                    candidatosAtivos.add(info);
                } else {
                    info.setAtivo(false);
                }
            }
        }

        if (candidatosAtivos.isEmpty()) {
            return null;
        }

        // Seleciona entre os servidores ativos (rodízio/round-robin para distribuir entre os ativos)
        int idx = Math.abs(indiceRodizio.getAndIncrement() % candidatosAtivos.size());
        return candidatosAtivos.get(idx);
    }

    private boolean verificarServidorOnline(String host, int porta) {
        try (Socket s = new Socket(host, porta)) {
            OutputStream out = s.getOutputStream();
            out.write("PING".getBytes("UTF-8"));
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public static void main(String[] args) {
        new ServidorDiretorio();
    }
}
