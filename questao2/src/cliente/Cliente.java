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

import javax.crypto.SecretKey;

import diretorio.ServidorDiretorio;
import log.Color;
import seguranca.CriptoUtils;
import seguranca.EnvelopeCriptografico;

public class Cliente {
    private final String nomeCliente;
    private final String hostDiretorio;
    private final int portaDiretorio;

    private final KeyPair parChavesRSA;
    private final SecretKey chaveAESDiretorio;
    private final SecretKey chaveHMACDiretorio;

    public Cliente(String nomeCliente, String hostDiretorio, int portaDiretorio) {
        this(nomeCliente, hostDiretorio, portaDiretorio, true);
    }

    public Cliente(String nomeCliente, String hostDiretorio, int portaDiretorio, boolean iniciarMenuInterativo) {
        this.nomeCliente = nomeCliente;
        this.hostDiretorio = hostDiretorio;
        this.portaDiretorio = portaDiretorio;

        this.parChavesRSA = CriptoUtils.gerarParChavesRSA();
        this.chaveAESDiretorio = CriptoUtils.gerarChaveAES();
        this.chaveHMACDiretorio = CriptoUtils.gerarChaveHMAC();

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
            Color.sucesso("[" + nomeCliente + "] Canal seguro (RSA+AES+HMAC) estabelecido com o Servidor de Diretório!");

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
                        enviarEnvelopeDiretorio(escritorDir, "LIST", false);
                        String listagem = lerEnvelopeDiretorio(leitorDir);
                        Color.info("\n" + listagem + "\n");
                        break;

                    case "1":
                        descobrirECalcularInterativo("Calcular soma", escritorDir, leitorDir, teclado, false);
                        break;

                    case "2":
                        descobrirECalcularInterativo("Calcular subtracao", escritorDir, leitorDir, teclado, false);
                        break;

                    case "3":
                        descobrirECalcularInterativo("Calcular multiplicacao", escritorDir, leitorDir, teclado, false);
                        break;

                    case "4":
                        descobrirECalcularInterativo("Calcular divisao", escritorDir, leitorDir, teclado, false);
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
                        enviarEnvelopeDiretorio(escritorDir, "STATUS|" + nomeSrv + "|" + statusSrv, false);
                        Color.sucesso("Resposta do Diretório: " + lerEnvelopeDiretorio(leitorDir) + "\n");
                        break;

                    case "6":
                        System.out.print("Digite o nome do serviço a consultar (ex: Calcular soma / Calcular modulo): ");
                        String servicoPersonalizado = teclado.nextLine().trim();
                        descobrirECalcularInterativo(servicoPersonalizado, escritorDir, leitorDir, teclado, false);
                        break;

                    case "7":
                        Color.alerta(">>> Simulando envio de pacote com falha de integridade (HMAC corrompido)...");
                        descobrirECalcularInterativo("Calcular soma", escritorDir, leitorDir, teclado, true);
                        break;

                    case "8":
                        enviarEnvelopeDiretorio(escritorDir, "QUIT", false);
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
            Scanner teclado,
            boolean corromperHmacNoCalculo) throws IOException {

        enviarEnvelopeDiretorio(escritorDir, "DISCOVER|" + operacao, false);
        String respostaDir = lerEnvelopeDiretorio(leitorDir);

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
            enviarEnvelopeDiretorio(escritorDir, "DISCOVER|" + servicoSolicitado, false);
            String respostaDir = lerEnvelopeDiretorio(leitorDir);

            if (respostaDir.startsWith("ERRO_ENTRADA|")) {
                String msgErro = respostaDir.substring("ERRO_ENTRADA|".length());
                Color.erro(msgErro);
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
                Color.info("[" + nomeCliente + "] Nó selecionado pelo balanceador (Round-Robin): "
                        + nomeServidor + " (" + ip + ":" + porta + ")");
            } else {
                Color.alerta("[" + nomeCliente + "] Resposta do Diretório: " + respostaDir);
            }

            enviarEnvelopeDiretorio(escritorDir, "QUIT", false);
            return respostaDir;
        } catch (Exception e) {
            Color.erro("[" + nomeCliente + "] Falha ao consultar o Diretório: " + e.getMessage());
            return "ERRO|" + e.getMessage();
        }
    }

    /**
     * Descobre o serviço no Diretório e executa a operação matemática no servidor selecionado pelo Load Balancer,
     * abrindo uma sessão cifrada (AES + HMAC + RSA) individual com o servidor selecionado.
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
     * Abre uma sessão cifrada (AES + HMAC + Assinatura RSA) exclusiva com o Servidor de Cálculo selecionado.
     */
    public String executarChamadaServidorCalculo(
            String nomeServidor,
            String ipSimulado,
            int portaServidor,
            String operacao,
            String num1,
            String num2,
            boolean enviarHmacCorrompido) {

        // Gera chaves simétricas (AES e HMAC) exclusivas para esta sessão individual com o servidor selecionado
        SecretKey chaveSessaoAES = CriptoUtils.gerarChaveAES();
        SecretKey chaveSessaoHMAC = CriptoUtils.gerarChaveHMAC();

        try (
                Socket socketCalc = new Socket("localhost", portaServidor);
                PrintWriter escritorCalc = new PrintWriter(
                        new OutputStreamWriter(socketCalc.getOutputStream(), StandardCharsets.UTF_8), true);
                BufferedReader leitorCalc = new BufferedReader(
                        new InputStreamReader(socketCalc.getInputStream(), StandardCharsets.UTF_8))
        ) {
            socketCalc.setSoTimeout(3000);
            String reqCalculo = "CALC|" + operacao + "|" + num1 + "|" + num2;

            String envelopeEnvio;
            if (enviarHmacCorrompido) {
                envelopeEnvio = EnvelopeCriptografico.criarEnvelopeComHmacCorrompido(
                        reqCalculo,
                        chaveSessaoAES,
                        chaveSessaoHMAC,
                        parChavesRSA,
                        nomeCliente
                );
            } else {
                envelopeEnvio = EnvelopeCriptografico.criarEnvelope(
                        reqCalculo,
                        chaveSessaoAES,
                        chaveSessaoHMAC,
                        parChavesRSA,
                        nomeCliente
                );
            }

            escritorCalc.println(envelopeEnvio);

            String linhaResposta = leitorCalc.readLine();
            if (linhaResposta == null) {
                Color.erro("[" + nomeCliente + " - ERRO] Servidor " + nomeServidor + " fechou a conexão sem responder.");
                return "ERRO_CONEXAO|Sem resposta";
            }

            EnvelopeCriptografico envelopeResp = EnvelopeCriptografico.abrirEValidarEnvelope(linhaResposta, nomeCliente);
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

    private void enviarEnvelopeDiretorio(PrintWriter escritorDir, String mensagemPlano, boolean corromperHmac) {
        String envelope;
        if (corromperHmac) {
            envelope = EnvelopeCriptografico.criarEnvelopeComHmacCorrompido(
                    mensagemPlano,
                    chaveAESDiretorio,
                    chaveHMACDiretorio,
                    parChavesRSA,
                    nomeCliente
            );
        } else {
            envelope = EnvelopeCriptografico.criarEnvelope(
                    mensagemPlano,
                    chaveAESDiretorio,
                    chaveHMACDiretorio,
                    parChavesRSA,
                    nomeCliente
            );
        }
        escritorDir.println(envelope);
    }

    private String lerEnvelopeDiretorio(BufferedReader leitorDir) throws IOException {
        String linha = leitorDir.readLine();
        if (linha == null) {
            return "";
        }
        try {
            EnvelopeCriptografico env = EnvelopeCriptografico.abrirEValidarEnvelope(linha, nomeCliente);
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

    public static void main(String[] args) {
        String nome = (args.length > 0) ? args[0] : "Cliente1";
        new Cliente(nome, "localhost", ServidorDiretorio.PORTA_DIRETORIO, true);
    }
}
