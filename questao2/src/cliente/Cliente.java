package cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Scanner;

import diretorio.ServidorDiretorio;
import log.Color;
import seguranca.CriptoUtils;
import seguranca.EnvelopeCriptografico;
import seguranca.SessaoSegura;

public class Cliente {
    private final String nomeCliente;
    private final String hostDiretorio;
    private final int portaDiretorio;

    private final KeyPair parChavesRSA;

    public Cliente(String nomeCliente, String hostDiretorio, int portaDiretorio) {
        this(nomeCliente, hostDiretorio, portaDiretorio, true);
    }

    public Cliente(String nomeCliente, String hostDiretorio, int portaDiretorio, boolean iniciarMenuInterativo) {
        this.nomeCliente = nomeCliente;
        this.hostDiretorio = hostDiretorio;
        this.portaDiretorio = portaDiretorio;

        this.parChavesRSA = CriptoUtils.gerarParChavesRSA();

        if (iniciarMenuInterativo) {
            rodarMenuInterativo();
        }
    }

    private void rodarMenuInterativo() {
        try (
                Socket socketDiretorio = new Socket(hostDiretorio, portaDiretorio);
                PrintWriter escritorDir = new PrintWriter(
                        new OutputStreamWriter(socketDiretorio.getOutputStream(), StandardCharsets.UTF_8), true);
                BufferedReader leitorDir = new BufferedReader(
                        new InputStreamReader(socketDiretorio.getInputStream(), StandardCharsets.UTF_8))
        ) {
            long pid = ProcessHandle.current().pid();
            SessaoSegura sessaoDir = SessaoSegura.realizarHandshakeComoCliente(
                    leitorDir,
                    escritorDir,
                    nomeCliente,
                    parChavesRSA
            );
            Color.sucesso("[" + nomeCliente + " | PID=" + pid
                    + "] Canal seguro (Handshake RSA + AES + HMAC) estabelecido com o Servidor de Diretório!");

            @SuppressWarnings("resource")
            Scanner teclado = new Scanner(System.in);

            while (true) {
                menu();

                if (!teclado.hasNextLine()) {
                    return;
                }
                String opcao = teclado.nextLine().trim();

                switch (opcao) {
                    case "0":
                        enviarEnvelopeDiretorio(escritorDir, sessaoDir, "LIST", false);
                        String listagem = lerEnvelopeDiretorio(leitorDir, sessaoDir);
                        Color.info("\n" + listagem + "\n");
                        break;

                    case "1":
                        descobrirECalcularInterativo("Calcular soma", escritorDir, leitorDir, sessaoDir, teclado, false);
                        break;

                    case "2":
                        descobrirECalcularInterativo("Calcular subtracao", escritorDir, leitorDir, sessaoDir, teclado, false);
                        break;

                    case "3":
                        descobrirECalcularInterativo("Calcular multiplicacao", escritorDir, leitorDir, sessaoDir, teclado, false);
                        break;

                    case "4":
                        descobrirECalcularInterativo("Calcular divisao", escritorDir, leitorDir, sessaoDir, teclado, false);
                        break;

                    case "5":
                        System.out.print("Qual o nome do servidor? (ex: S1, S2, S3): ");
                        String nomeSrv = teclado.nextLine().trim();
                        System.out.print("Qual o novo status? (ATIVO / INATIVO): ");
                        String statusSrv = teclado.nextLine().trim().toUpperCase();
                        if (!statusSrv.equals("ATIVO") && !statusSrv.equals("INATIVO")) {
                            Color.erro("Erro na entrada de dados. Tente outra vez!\n");
                            break;
                        }
                        enviarEnvelopeDiretorio(escritorDir, sessaoDir, "STATUS|" + nomeSrv + "|" + statusSrv, false);
                        Color.sucesso("Resposta do Diretório: " + lerEnvelopeDiretorio(leitorDir, sessaoDir) + "\n");
                        break;

                    case "6":
                        System.out.print("Digite o nome do serviço a consultar (ex: Calcular soma / Calcular modulo): ");
                        String servicoPersonalizado = teclado.nextLine().trim();
                        descobrirECalcularInterativo(servicoPersonalizado, escritorDir, leitorDir, sessaoDir, teclado, false);
                        break;

                    case "7":
                        Color.alerta(">>> Simulando envio de pacote com falha de integridade (HMAC corrompido)...");
                        descobrirECalcularInterativo("Calcular soma", escritorDir, leitorDir, sessaoDir, teclado, true);
                        break;

                    case "8":
                        enviarEnvelopeDiretorio(escritorDir, sessaoDir, "QUIT", false);
                        Color.info("[" + nomeCliente + "] Desconectando do Servidor de Diretório...");
                        return;

                    default:
                        Color.erro("Erro na entrada de dados. Tente outra vez!\n");
                        break;
                }
            }
        } catch (IOException e) {
            Color.erro("[" + nomeCliente + "] Erro ao se comunicar com o Servidor de Diretório: " + e.getMessage());
        }
    }

    private void descobrirECalcularInterativo(
            String operacao,
            PrintWriter escritorDir,
            BufferedReader leitorDir,
            SessaoSegura sessaoDir,
            Scanner teclado,
            boolean corromperHmacNoCalculo) throws IOException {

        enviarEnvelopeDiretorio(escritorDir, sessaoDir, "DISCOVER|" + operacao, false);
        String respostaDir = lerEnvelopeDiretorio(leitorDir, sessaoDir);

        if (respostaDir.startsWith("ERRO_ENTRADA|")) {
            Color.erro(respostaDir.substring("ERRO_ENTRADA|".length()) + "\n");
            return;
        }

        if (respostaDir.startsWith("ERRO|") || respostaDir.startsWith("ERRO_HMAC|")) {
            Color.erro("[Diretório]: " + respostaDir.substring(respostaDir.indexOf('|') + 1) + "\n");
            return;
        }

        // OK|nomeSelecionado|ipSelecionado|portaSelecionada|listaServidoresAtivos
        String[] partes = respostaDir.split("\\|");
        if (partes.length >= 4 && partes[0].equals("OK")) {
            String nomeServidor = partes[1];
            String ip = partes[2];
            int portaServidor = Integer.parseInt(partes[3]);
            String listaAtivos = (partes.length >= 5) ? partes[4] : (nomeServidor + "(" + ip + ":" + portaServidor + ")");

            Color.info(">>> [" + nomeCliente + " - Descoberta Segura] Lista de servidores ativos autenticada para '"
                    + operacao + "': [" + listaAtivos + "]");
            Color.sucesso(">>> [" + nomeCliente + " - Load Balancing] Servidor selecionado pelo Diretório: "
                    + nomeServidor + " (Endereço: " + ip + ", Porta: " + portaServidor + ")");

            System.out.print("Digite o primeiro número: ");
            String num1 = teclado.nextLine().trim();
            System.out.print("Digite o segundo número: ");
            String num2 = teclado.nextLine().trim();

            try {
                Double.parseDouble(num1);
                Double.parseDouble(num2);
            } catch (NumberFormatException e) {
                Color.erro("Erro na entrada de dados. Tente outra vez!\n");
                return;
            }

            executarChamadaServidorCalculo(nomeServidor, ip, portaServidor, operacao, num1, num2, corromperHmacNoCalculo);
        } else {
            Color.erro("Resposta inesperada do Diretório: " + respostaDir);
        }
    }

    public String descobrirServicoNoDiretorio(String servicoSolicitado) {
        try (
                Socket socketDir = new Socket(hostDiretorio, portaDiretorio);
                PrintWriter escritorDir = new PrintWriter(
                        new OutputStreamWriter(socketDir.getOutputStream(), StandardCharsets.UTF_8), true);
                BufferedReader leitorDir = new BufferedReader(
                        new InputStreamReader(socketDir.getInputStream(), StandardCharsets.UTF_8))
        ) {
            // 1. Handshake RSA com o Diretório para estabelecer chaves de sessão (AES + HMAC)
            SessaoSegura sessaoDir = SessaoSegura.realizarHandshakeComoCliente(
                    leitorDir,
                    escritorDir,
                    nomeCliente,
                    parChavesRSA
            );

            // 2. Solicita a descoberta do serviço cifrada na sessão
            enviarEnvelopeDiretorio(escritorDir, sessaoDir, "DISCOVER|" + servicoSolicitado, false);
            String respostaDir = lerEnvelopeDiretorio(leitorDir, sessaoDir);

            if (respostaDir.startsWith("ERRO_ENTRADA|")) {
                String msgErro = respostaDir.substring("ERRO_ENTRADA|".length());
                Color.erro(msgErro);
                enviarEnvelopeDiretorio(escritorDir, sessaoDir, "QUIT", false);
                return respostaDir;
            }

            if (respostaDir.startsWith("OK|")) {
                String[] partes = respostaDir.split("\\|");
                String nomeServidor = partes[1];
                String ip = partes[2];
                String porta = partes[3];
                String listaAtivos = (partes.length >= 5) ? partes[4] : (nomeServidor + "(" + ip + ":" + porta + ")");

                Color.sucesso("[" + nomeCliente + "] Lista de servidores ativos autenticada para '"
                        + servicoSolicitado + "': [" + listaAtivos + "]");
                Color.info("[" + nomeCliente + "] Nó selecionado pelo balanceador: "
                        + nomeServidor + " (" + ip + ":" + porta + ")");
            } else {
                Color.alerta("[" + nomeCliente + "] Resposta do Diretório: " + respostaDir);
            }

            enviarEnvelopeDiretorio(escritorDir, sessaoDir, "QUIT", false);
            return respostaDir;
        } catch (Exception e) {
            Color.erro("[" + nomeCliente + "] Falha ao consultar o Diretório: " + e.getMessage());
            return "ERRO|" + e.getMessage();
        }
    }

    /**
     * Descobre o serviço no Diretório e executa a operação matemática no servidor selecionado pelo Load Balancer,
     * abrindo uma sessão cifrada (Handshake RSA + AES + HMAC + Assinatura RSA) individual com o servidor selecionado.
     */
    public String descobrirECalcular(String servicoSolicitado, double num1, double num2, boolean corromperHmac) {
        String respostaDir = descobrirServicoNoDiretorio(servicoSolicitado);
        if (!respostaDir.startsWith("OK|")) {
            return respostaDir;
        }

        String[] partes = respostaDir.split("\\|");
        String nomeServidor = partes[1];
        String ip = partes[2];
        int portaServidor = Integer.parseInt(partes[3]);

        return executarChamadaServidorCalculo(
                nomeServidor,
                ip,
                portaServidor,
                servicoSolicitado,
                String.valueOf(num1),
                String.valueOf(num2),
                corromperHmac
        );
    }

    /**
     * Abre uma sessão cifrada (Handshake RSA + AES + HMAC + Assinatura RSA) exclusiva com o Servidor de Cálculo selecionado.
     */
    public String executarChamadaServidorCalculo(
            String nomeServidor,
            String ipSimulado,
            int portaServidor,
            String operacao,
            String num1,
            String num2,
            boolean enviarHmacCorrompido) {

        try (
                Socket socketCalc = new Socket("localhost", portaServidor);
                PrintWriter escritorCalc = new PrintWriter(
                        new OutputStreamWriter(socketCalc.getOutputStream(), StandardCharsets.UTF_8), true);
                BufferedReader leitorCalc = new BufferedReader(
                        new InputStreamReader(socketCalc.getInputStream(), StandardCharsets.UTF_8))
        ) {
            socketCalc.setSoTimeout(3000);

            // 1. Handshake RSA com o Servidor de Cálculo para negociar chaves AES e HMAC exclusivas da sessão
            SessaoSegura sessaoCalc = SessaoSegura.realizarHandshakeComoCliente(
                    leitorCalc,
                    escritorCalc,
                    nomeCliente,
                    parChavesRSA
            );

            String reqCalculo = "CALC|" + operacao + "|" + num1 + "|" + num2;

            String envelopeEnvio;
            if (enviarHmacCorrompido) {
                envelopeEnvio = sessaoCalc.empacotarMensagemComHmacCorrompido(reqCalculo);
            } else {
                envelopeEnvio = sessaoCalc.empacotarMensagem(reqCalculo);
            }

            escritorCalc.println(envelopeEnvio);

            String linhaResposta = leitorCalc.readLine();
            if (linhaResposta == null) {
                Color.erro("[" + nomeCliente + " - ERRO] Servidor " + nomeServidor + " fechou a conexão sem responder.");
                return "ERRO_CONEXAO|Sem resposta";
            }

            EnvelopeCriptografico envelopeResp = sessaoCalc.desempacotarEValidar(linhaResposta);
            String resultado = envelopeResp.getMensagemOriginal();

            if (resultado.startsWith("ERRO_ENTRADA|")) {
                String msgErro = resultado.substring("ERRO_ENTRADA|".length());
                Color.erro(msgErro);
                return resultado;
            }

            if (resultado.startsWith("ERRO_HMAC|")) {
                Color.erro("[" + nomeCliente + " - EXECUÇÃO REJEITADA] " + resultado.substring("ERRO_HMAC|".length()));
                return resultado;
            }

            Color.sucesso(">>> [" + nomeCliente + " <- " + nomeServidor + "] " + resultado + "\n");
            return resultado;

        } catch (SecurityException se) {
            Color.erro("[" + nomeCliente + " - TRATAMENTO DE ERRO DE INTEGRIDADE] "
                    + "HMAC/Assinatura de " + nomeServidor + " corrompido! Execução rejeitada com segurança: "
                    + se.getMessage() + "\n");
            return "ERRO_HMAC|" + se.getMessage();
        } catch (IOException e) {
            String msgInativo = "[" + nomeCliente + " - TRATAMENTO DE ERRO DE CONEXÃO] "
                    + "Servidor " + nomeServidor + " (" + ipSimulado + ":" + portaServidor
                    + ") está inativo/indisponível. Execução abortada sem travar o cliente (" + e.getMessage() + ").";
            EnvelopeCriptografico.registrarLog("ERRO", msgInativo);
            System.out.println();
            return "ERRO_CONEXAO|" + e.getMessage();
        }
    }

    private void enviarEnvelopeDiretorio(
            PrintWriter escritorDir,
            SessaoSegura sessaoDir,
            String mensagemPlano,
            boolean corromperHmac) {
        String envelope = corromperHmac
                ? sessaoDir.empacotarMensagemComHmacCorrompido(mensagemPlano)
                : sessaoDir.empacotarMensagem(mensagemPlano);
        escritorDir.println(envelope);
    }

    private String lerEnvelopeDiretorio(BufferedReader leitorDir, SessaoSegura sessaoDir) throws IOException {
        String linha = leitorDir.readLine();
        if (linha == null) {
            return "";
        }
        try {
            EnvelopeCriptografico env = sessaoDir.desempacotarEValidar(linha);
            return env.getMensagemOriginal();
        } catch (SecurityException se) {
            Color.erro("[" + nomeCliente + " - ALERTA] Resposta do Diretório com HMAC inválido: " + se.getMessage());
            return "ERRO_HMAC|" + se.getMessage();
        }
    }

    private void menu() {
        System.out.println(Color.CIANO_BRILHANTE + "=========================================================" + Color.RESET);
        System.out.println(Color.NEGRITO + "OPERAÇÕES DE DESCOBERTA DE SERVIÇOS SEGURA (" + nomeCliente + "):" + Color.RESET);
        System.out.println(
                "0 - Listar servidores registrados\n" +
                "1 - Calcular soma\n" +
                "2 - Calcular subtração\n" +
                "3 - Calcular multiplicação\n" +
                "4 - Calcular divisão\n" +
                "5 - Alterar STATUS de um servidor\n" +
                "6 - Consultar serviço personalizado (ex: Calcular modulo)\n" +
                "7 - Simular falha de integridade (HMAC corrompido)\n" +
                "8 - Encerrar conexão"
        );
        System.out.print("Selecione uma operação: ");
    }

    /**
     * Permite executar cada Cliente como um processo independente (interativo ou automatizado):
     * Exemplos:
     *   java cliente.Cliente "Cliente 1"
     *   java cliente.Cliente "Cliente 1" --discover "Calcular soma"
     *   java cliente.Cliente "Cliente 1" --calc "Calcular soma" 10 20 false
     */
    public static void main(String[] args) {
        String nome = (args.length > 0) ? args[0] : "Cliente 1";
        if (args.length >= 3 && args[1].equalsIgnoreCase("--discover")) {
            Cliente c = new Cliente(nome, "localhost", ServidorDiretorio.PORTA_DIRETORIO, false);
            c.descobrirServicoNoDiretorio(args[2]);
            return;
        }
        if (args.length >= 6 && args[1].equalsIgnoreCase("--calc")) {
            Cliente c = new Cliente(nome, "localhost", ServidorDiretorio.PORTA_DIRETORIO, false);
            double n1 = Double.parseDouble(args[3]);
            double n2 = Double.parseDouble(args[4]);
            boolean corromper = Boolean.parseBoolean(args[5]);
            c.descobrirECalcular(args[2], n1, n2, corromper);
            return;
        }
        new Cliente(nome, "localhost", ServidorDiretorio.PORTA_DIRETORIO, true);
    }
}
