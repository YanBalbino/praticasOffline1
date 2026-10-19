package servidor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import diretorio.ServidorDiretorio;
import log.Color;
import model.InfoServidor;
import seguranca.CriptoUtils;
import seguranca.EnvelopeCriptografico;
import seguranca.SessaoSegura;

public class ServidorCalculadora {
    private final String nome;
    private final String endereco;
    private final int porta;
    private final String hostDiretorio;
    private final int portaDiretorio;

    private final KeyPair parChavesRSA;

    private ServerSocket serverSocket;
    private volatile boolean executando = true;
    private volatile boolean simularHmacCorrompido = false;

    public ServidorCalculadora(String nome, String endereco, int porta, String hostDiretorio, int portaDiretorio) {
        this(nome, endereco, porta, hostDiretorio, portaDiretorio, true);
    }

    public ServidorCalculadora(
            String nome,
            String endereco,
            int porta,
            String hostDiretorio,
            int portaDiretorio,
            boolean modoAssincrono) {
        this.nome = nome;
        this.endereco = endereco;
        this.porta = porta;
        this.hostDiretorio = hostDiretorio;
        this.portaDiretorio = portaDiretorio;

        this.parChavesRSA = CriptoUtils.gerarParChavesRSA();

        if (modoAssincrono) {
            new Thread(this::rodar, "Thread-" + nome).start();
        } else {
            rodar();
        }
    }

    private void rodar() {
        try {
            serverSocket = new ServerSocket(porta);
            long pid = ProcessHandle.current().pid();
            Color.info("[" + nome + " | PID=" + pid + "] Rodando em " + endereco
                    + " (porta real: " + porta + ") com Handshake RSA + AES + HMAC...");

            // Registra-se no Servidor de Diretório usando sessão e pacote cifrado (RSA+AES+HMAC)
            registrarNoDiretorio();

            while (executando) {
                Socket cliente = serverSocket.accept();
                atenderCliente(cliente);
            }
        } catch (IOException e) {
            if (executando) {
                Color.erro("[" + nome + "] Erro no servidor: " + e.getMessage());
            }
        } finally {
            pararServidor();
        }
    }

    private void registrarNoDiretorio() {
        try (
                Socket socketDir = new Socket(hostDiretorio, portaDiretorio);
                PrintWriter escritor = new PrintWriter(
                        new OutputStreamWriter(socketDir.getOutputStream(), StandardCharsets.UTF_8), true);
                BufferedReader leitor = new BufferedReader(
                        new InputStreamReader(socketDir.getInputStream(), StandardCharsets.UTF_8))
        ) {
            // 1. Handshake RSA com o Diretório para estabelecer chaves simétricas de sessão (AES + HMAC)
            SessaoSegura sessaoDir = SessaoSegura.realizarHandshakeComoCliente(
                    leitor,
                    escritor,
                    nome,
                    parChavesRSA
            );

            // 2. Envia o comando REGISTER cifrado na sessão
            String servicos = "SOMA,SUBTRACAO,MULTIPLICACAO,DIVISAO";
            String msgRegistro = "REGISTER|" + nome + "|" + endereco + "|" + porta + "|" + servicos;
            escritor.println(sessaoDir.empacotarMensagem(msgRegistro));

            // 3. Recebe e valida a confirmação do Diretório na mesma sessão
            String linhaResposta = leitor.readLine();
            if (linhaResposta != null) {
                EnvelopeCriptografico respostaEnv = sessaoDir.desempacotarEValidar(linhaResposta);
                Color.sucesso("[" + nome + "] Resposta autenticada do Diretório: " + respostaEnv.getMensagemOriginal());
            }

            escritor.println(sessaoDir.empacotarMensagem("QUIT"));
        } catch (Exception e) {
            Color.erro("[" + nome + "] Não foi possível registrar no Diretório: " + e.getMessage());
        }
    }

    private void atenderCliente(Socket cliente) {
        new Thread(() -> {
            try (
                    BufferedReader leitor = new BufferedReader(
                            new InputStreamReader(cliente.getInputStream(), StandardCharsets.UTF_8));
                    PrintWriter escritor = new PrintWriter(
                            new OutputStreamWriter(cliente.getOutputStream(), StandardCharsets.UTF_8), true)
            ) {
                // 1. Handshake RSA atuando como Servidor para estabelecer a sessão individual (AES + HMAC)
                SessaoSegura sessao;
                try {
                    sessao = SessaoSegura.realizarHandshakeComoServidor(
                            leitor,
                            escritor,
                            nome,
                            parChavesRSA
                    );
                    if (sessao == null) {
                        return;
                    }
                } catch (SecurityException se) {
                    Color.erro("[" + nome + " - ALERTA DE SEGURANÇA] Falha no Handshake RSA: " + se.getMessage());
                    return;
                }

                String linhaRecebida = leitor.readLine();
                if (linhaRecebida == null) {
                    return;
                }
                linhaRecebida = linhaRecebida.trim();

                EnvelopeCriptografico envelopeReq;
                try {
                    envelopeReq = sessao.desempacotarEValidar(linhaRecebida);
                } catch (SecurityException se) {
                    Color.erro("[" + nome + " - ALERTA DE SEGURANÇA] Execução rejeitada! " + se.getMessage());
                    String envErro = sessao.empacotarMensagem(
                            "ERRO_HMAC|Execução rejeitada por " + nome + ": HMAC corrompido ou assinatura inválida!"
                    );
                    escritor.println(envErro);
                    return;
                }

                String msg = envelopeReq.getMensagemOriginal().trim();

                // Health-check PING/PONG cifrado
                if (msg.equals("PING")) {
                    escritor.println(sessao.empacotarMensagem("PONG"));
                    return;
                }

                // Comando administrativo seguro para ativar/desativar simulação de HMAC corrompido (Caso 3B em processo isolado)
                if (msg.startsWith("CONFIG_HMAC_CORROMPIDO|")) {
                    boolean ativar = Boolean.parseBoolean(msg.substring("CONFIG_HMAC_CORROMPIDO|".length()).trim());
                    setSimularHmacCorrompido(ativar);
                    escritor.println(sessao.empacotarMensagem("OK|Simulação de HMAC corrompido em " + nome + " = " + ativar));
                    return;
                }

                // Comando administrativo seguro para encerrar o processo do servidor (Caso 3D)
                if (msg.equals("SHUTDOWN")) {
                    escritor.println(sessao.empacotarMensagem("OK|Encerrando servidor " + nome));
                    pararServidor();
                    return;
                }

                // CALC|OPERACAO|num1|num2
                if (msg.startsWith("CALC|")) {
                    String[] partes = msg.split("\\|");
                    String respostaPlano;

                    if (partes.length == 4) {
                        String operacao = InfoServidor.normalizarOperacao(partes[1].trim());
                        try {
                            double a = Double.parseDouble(partes[2].trim());
                            double b = Double.parseDouble(partes[3].trim());
                            respostaPlano = processarCalculo(operacao, a, b);
                            Color.sucesso("[" + nome + " - " + endereco + "] Atendeu '" + operacao
                                    + "' na sessão com '" + envelopeReq.getNomeEmissor() + "' -> " + respostaPlano);
                        } catch (NumberFormatException nfe) {
                            respostaPlano = "ERRO_ENTRADA|Erro na entrada de dados. Tente outra vez!";
                        }
                    } else {
                        respostaPlano = "ERRO_ENTRADA|Erro na entrada de dados. Tente outra vez!";
                    }

                    String envelopeResposta;
                    if (simularHmacCorrompido) {
                        Color.alerta("[" + nome + "] Simulando envio de pacote na sessão com HMAC adulterado/corrompido...");
                        envelopeResposta = sessao.empacotarMensagemComHmacCorrompido(respostaPlano);
                    } else {
                        envelopeResposta = sessao.empacotarMensagem(respostaPlano);
                    }
                    escritor.println(envelopeResposta);
                } else {
                    escritor.println(sessao.empacotarMensagem("ERRO_ENTRADA|Erro na entrada de dados. Tente outra vez!"));
                }
            } catch (Exception e) {
                Color.erro("[" + nome + "] Erro ao atender cliente: " + e.getMessage());
            } finally {
                try {
                    cliente.close();
                } catch (IOException e) {
                    // Ignora erro ao fechar conexão
                }
            }
        }).start();
    }

    private String processarCalculo(String operacao, double a, double b) {
        double resultado;
        String simbolo;

        switch (operacao) {
            case "SOMA":
                resultado = a + b;
                simbolo = "+";
                break;
            case "SUBTRACAO":
                resultado = a - b;
                simbolo = "-";
                break;
            case "MULTIPLICACAO":
                resultado = a * b;
                simbolo = "*";
                break;
            case "DIVISAO":
                if (b == 0) {
                    return "ERRO|Divisão por zero não permitida!";
                }
                resultado = a / b;
                simbolo = "/";
                break;
            default:
                return "ERRO_ENTRADA|Erro na entrada de dados. Tente outra vez!";
        }

        return "RESULTADO [" + nome + " (" + endereco + ")]: " + a + " " + simbolo + " " + b + " = " + resultado;
    }

    public void setSimularHmacCorrompido(boolean simularHmacCorrompido) {
        this.simularHmacCorrompido = simularHmacCorrompido;
    }

    public void pararServidor() {
        executando = false;
        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
                Color.alerta("[" + nome + "] Servidor encerrado (inativo).");
            } catch (IOException e) {
                // Ignora erro ao fechar
            }
        }
    }

    public String getNome() {
        return nome;
    }

    public int getPorta() {
        return porta;
    }
}
