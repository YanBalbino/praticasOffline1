package cliente;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import diretorio.ServidorDiretorio;
import log.Color;
import seguranca.CriptoUtils;
import seguranca.SessaoSegura;
import servidor.ServidorCalculadora;

public class SimuladorCasosTeste {

    private static final List<Process> PROCESSOS_ATIVOS = new ArrayList<Process>();
    private static boolean usarSubprocessosSO = true;

    private static ServidorDiretorio diretorioLocal;
    private static ServidorCalculadora s1Local;
    private static ServidorCalculadora s2Local;
    private static ServidorCalculadora s3Local;

    public static void main(String[] args) throws Exception {
        System.setProperty("jdk.lang.Process.launchMechanism", "FORK");
        Runtime.getRuntime().addShutdownHook(new Thread(SimuladorCasosTeste::encerrarTodosProcessos));

        Color.info("====================================================================================");
        Color.info("  SIMULAÇÃO DOS CASOS DE TESTE - CAMADA DE SEGURANÇA HÍBRIDA (RSA + AES + HMAC)");
        Color.info("====================================================================================\n");

        try {
            // =========================================================================
            // CASO 1: Descoberta de serviço e cifra híbrida no diretório
            // =========================================================================
            Color.info("------------------------------------------------------------------------------------");
            Color.info("CASO 1: Descoberta de serviço e cifra híbrida no Diretório");
            Color.info("Participantes: Cliente 1, Servidor de Diretório e Servidores de Calc (S1, S2, S3)");
            Color.info("------------------------------------------------------------------------------------");

            Process procDiretorio = iniciarDiretorio();
            aguardarPortaAberta(ServidorDiretorio.PORTA_DIRETORIO, 5000);

            // S1, S2 e S3 registram seus serviços no Diretório usando Handshake RSA + pacotes cifrados (RSA+AES+HMAC)
            Process procS1 = iniciarServidorCalc("S1", "192.168.0.101", 7001, "impl.ImplServidorS1");
            aguardarPortaAberta(7001, 5000);

            Process procS2 = iniciarServidorCalc("S2", "192.168.0.102", 7002, "impl.ImplServidorS2");
            aguardarPortaAberta(7002, 5000);

            Process procS3 = iniciarServidorCalc("S3", "192.168.0.103", 7003, "impl.ImplServidorS3");
            aguardarPortaAberta(7003, 5000);
            Thread.sleep(400);

            // Cliente 1 estabelece canal seguro com o Diretório e solicita o serviço "Calcular soma"
            Color.info("[Caso 1] Cliente 1 solicitando o serviço 'Calcular soma' ao Diretório...");
            executarAcaoCliente("Cliente 1", "--discover", "Calcular soma");
            Color.sucesso("[Caso 1 - Resultado] Logs do canal seguro gravados em tempo real em 'logs_canal_seguro.txt'.\n");

            // =========================================================================
            // CASO 2: Chamada de serviço com Load Balancing (Round-Robin)
            // =========================================================================
            Color.info("------------------------------------------------------------------------------------");
            Color.info("CASO 2: Chamada de serviço com Load Balancing (Round-Robin)");
            Color.info("Participantes: Cliente 1, Cliente 2 e Servidores de Calc (S1, S2)");
            Color.info("------------------------------------------------------------------------------------");

            // Para o Caso 2 (apenas S1 e S2 no balanceamento), marcamos S3 temporariamente como INATIVO no Diretório
            enviarComandoSeguroDiretorio("STATUS|S3|INATIVO");
            enviarComandoSeguroDiretorio("RESET_RODIZIO");
            Thread.sleep(200);

            // 1ª Chamada: Cliente 1 requisita 10 + 20 -> Round-Robin seleciona S1
            Color.info("[Caso 2 - 1ª Chamada] Cliente 1 requisitando cálculo: 10 + 20 (Calcular soma)...");
            executarAcaoCliente("Cliente 1", "--calc", "Calcular soma", "10", "20", "false");
            Thread.sleep(200);

            // 2ª Chamada: Cliente 2 requisita 5 * 4 -> Round-Robin alterna para S2
            Color.info("[Caso 2 - 2ª Chamada] Cliente 2 requisitando cálculo: 5 * 4 (Calcular multiplicacao)...");
            executarAcaoCliente("Cliente 2", "--calc", "Calcular multiplicacao", "5", "4", "false");
            Thread.sleep(200);

            // =========================================================================
            // CASO 3: Servidor inativo ou falha de integridade
            // =========================================================================
            Color.info("------------------------------------------------------------------------------------");
            Color.info("CASO 3: Servidor inativo ou falha de integridade");
            Color.info("Participantes: Cliente 3, Diretório e Servidor de Calc (S3 indisponível/adulterado)");
            Color.info("------------------------------------------------------------------------------------");

            // Subcaso 3A: Entrada inválida na consulta ao Diretório (operação "Calcular modulo" não cadastrada)
            Color.info("[Caso 3A - Entrada Inválida] Cliente 3 consultando serviço não cadastrado ('Calcular modulo'):");
            executarAcaoCliente("Cliente 3", "--discover", "Calcular modulo");
            System.out.println();
            Thread.sleep(200);

            // Prepara o Diretório para retornar S3 nas consultas do Cliente 3 (S3 ATIVO, S1 e S2 temporariamente INATIVOS)
            enviarComandoSeguroDiretorio("STATUS|S1|INATIVO");
            enviarComandoSeguroDiretorio("STATUS|S2|INATIVO");
            enviarComandoSeguroDiretorio("STATUS|S3|ATIVO");
            enviarComandoSeguroDiretorio("RESET_RODIZIO");

            // Subcaso 3B: Cliente 3 descobre S3 no Diretório e tenta negociar/calcular, mas o HMAC de S3 falha
            Color.info("[Caso 3B - Falha de Integridade (HMAC Corrompido no serviço S3 retornado pelo Diretório)]:");
            enviarComandoSeguroServidorCalc(7003, "CONFIG_HMAC_CORROMPIDO|true");
            executarAcaoCliente("Cliente 3", "--calc", "Calcular soma", "15", "25", "false");
            Thread.sleep(200);

            // Subcaso 3C: Cliente 3 descobre S3 no Diretório e envia pacote com HMAC corrompido para S3
            Color.info("[Caso 3C - Falha de Integridade (Pacote do Cliente 3 com HMAC Corrompido rejeitado por S3)]:");
            enviarComandoSeguroServidorCalc(7003, "CONFIG_HMAC_CORROMPIDO|false");
            executarAcaoCliente("Cliente 3", "--calc", "Calcular soma", "15", "25", "true");
            System.out.println();
            Thread.sleep(200);

            // Subcaso 3D: S3 fica inativo/indisponível -> Cliente 3 descobre S3 no Diretório e trata a falha de conexão sem travar
            Color.info("[Caso 3D - Servidor S3 Retornado pelo Diretório está Indisponível/Inativo]:");
            enviarComandoSeguroServidorCalc(7003, "SHUTDOWN");
            if (procS3 != null) {
                procS3.waitFor();
            } else if (s3Local != null) {
                s3Local.pararServidor();
            }
            Thread.sleep(200);
            executarAcaoCliente("Cliente 3", "--calc", "Calcular soma", "15", "25", "false");

            // Comprova que os demais componentes (Diretório, S1, S2) continuam funcionando normalmente sem travar
            Color.info("[Caso 3 - Verificação de Resiliência] Reativando S1 e S2 e confirmando operação normal:");
            enviarComandoSeguroDiretorio("STATUS|S1|ATIVO");
            enviarComandoSeguroDiretorio("STATUS|S2|ATIVO");
            enviarComandoSeguroDiretorio("STATUS|S3|INATIVO");
            enviarComandoSeguroDiretorio("RESET_RODIZIO");
            executarAcaoCliente("Cliente 1", "--calc", "Calcular soma", "100", "50", "false");

            // Encerra os processos/instâncias de S1, S2 e Diretório de forma limpa
            enviarComandoSeguroServidorCalc(7001, "SHUTDOWN");
            enviarComandoSeguroServidorCalc(7002, "SHUTDOWN");
            enviarComandoSeguroDiretorio("SHUTDOWN");

            if (procS1 != null) procS1.waitFor();
            if (procS2 != null) procS2.waitFor();
            if (procDiretorio != null) procDiretorio.waitFor();

            if (s1Local != null) s1Local.pararServidor();
            if (s2Local != null) s2Local.pararServidor();
            if (diretorioLocal != null) diretorioLocal.fechar();

            Color.sucesso("====================================================================================");
            Color.sucesso("  TODOS OS CASOS DE TESTE (1, 2 e 3) FORAM EXECUTADOS COM SUCESSO!");
            Color.sucesso("====================================================================================");
            System.exit(0);
        } finally {
            encerrarTodosProcessos();
        }
    }

    private static Process iniciarDiretorio() {
        if (usarSubprocessosSO) {
            try {
                return iniciarProcessoBackground("impl.ImplServidorDiretorio");
            } catch (IOException e) {
                usarSubprocessosSO = false;
            }
        }
        diretorioLocal = new ServidorDiretorio(true);
        return null;
    }

    private static Process iniciarServidorCalc(String nome, String ip, int porta, String classeMain) {
        if (usarSubprocessosSO) {
            try {
                return iniciarProcessoBackground(classeMain);
            } catch (IOException e) {
                usarSubprocessosSO = false;
            }
        }
        ServidorCalculadora srv = new ServidorCalculadora(nome, ip, porta, "localhost", ServidorDiretorio.PORTA_DIRETORIO, true);
        if ("S1".equals(nome)) s1Local = srv;
        else if ("S2".equals(nome)) s2Local = srv;
        else if ("S3".equals(nome)) s3Local = srv;
        return null;
    }

    private static void executarAcaoCliente(String nomeCliente, String... argsAcao) throws Exception {
        if (usarSubprocessosSO) {
            try {
                List<String> comando = new ArrayList<String>();
                comando.add(obterJavaBin());
                comando.add("-cp");
                comando.add(obterClassPath());
                comando.add("cliente.Cliente");
                comando.add(nomeCliente);
                for (String arg : argsAcao) {
                    comando.add(arg);
                }

                ProcessBuilder pb = new ProcessBuilder(comando);
                pb.inheritIO();
                Process proc = pb.start();
                proc.waitFor();
                return;
            } catch (IOException e) {
                usarSubprocessosSO = false;
            }
        }

        String[] cliArgs = new String[argsAcao.length + 1];
        cliArgs[0] = nomeCliente;
        System.arraycopy(argsAcao, 0, cliArgs, 1, argsAcao.length);
        Cliente.main(cliArgs);
    }

    private static String obterJavaBin() {
        return System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";
    }

    private static String obterClassPath() {
        return System.getProperty("java.class.path");
    }

    private static Process iniciarProcessoBackground(String classePrincipal, String... argsExtras) throws IOException {
        List<String> comando = new ArrayList<String>();
        comando.add(obterJavaBin());
        comando.add("-cp");
        comando.add(obterClassPath());
        comando.add(classePrincipal);
        for (String arg : argsExtras) {
            comando.add(arg);
        }

        ProcessBuilder pb = new ProcessBuilder(comando);
        pb.inheritIO();
        Process proc = pb.start();
        PROCESSOS_ATIVOS.add(proc);
        return proc;
    }

    private static void aguardarPortaAberta(int porta, long timeoutMs) throws InterruptedException {
        long inicio = System.currentTimeMillis();
        while (System.currentTimeMillis() - inicio < timeoutMs) {
            try (Socket s = new Socket("localhost", porta)) {
                return;
            } catch (Exception e) {
                Thread.sleep(100);
            }
        }
    }

    private static void enviarComandoSeguroDiretorio(String comando) {
        try (
                Socket socket = new Socket("localhost", ServidorDiretorio.PORTA_DIRETORIO);
                PrintWriter escritor = new PrintWriter(
                        new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);
                BufferedReader leitor = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))
        ) {
            KeyPair rsaAdmin = CriptoUtils.gerarParChavesRSA();
            SessaoSegura sessao = SessaoSegura.realizarHandshakeComoCliente(
                    leitor,
                    escritor,
                    "AdminOrquestrador",
                    rsaAdmin
            );
            escritor.println(sessao.empacotarMensagem(comando));
            leitor.readLine();
            if (!comando.equals("SHUTDOWN")) {
                escritor.println(sessao.empacotarMensagem("QUIT"));
            }
        } catch (Exception e) {
            // Ignora no encerramento
        }
    }

    private static void enviarComandoSeguroServidorCalc(int portaServidor, String comando) {
        try (
                Socket socket = new Socket("localhost", portaServidor);
                PrintWriter escritor = new PrintWriter(
                        new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);
                BufferedReader leitor = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))
        ) {
            KeyPair rsaAdmin = CriptoUtils.gerarParChavesRSA();
            SessaoSegura sessao = SessaoSegura.realizarHandshakeComoCliente(
                    leitor,
                    escritor,
                    "AdminOrquestrador",
                    rsaAdmin
            );
            escritor.println(sessao.empacotarMensagem(comando));
            leitor.readLine();
        } catch (Exception e) {
            // Ignora no encerramento
        }
    }

    private static void encerrarTodosProcessos() {
        for (Process p : PROCESSOS_ATIVOS) {
            if (p != null && p.isAlive()) {
                p.destroyForcibly();
            }
        }
    }
}
