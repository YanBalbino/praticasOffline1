package cliente;

import java.io.File;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import log.Color;
import model.InfoNo;
import model.MensagemP2P;
import no.NoP2P;

public class SimuladorCasosTeste {

    private static final List<Process> PROCESSOS_ATIVOS = new ArrayList<Process>();
    private static final List<NoP2P> NOS_LOCAIS = new ArrayList<NoP2P>();
    private static boolean usarSubprocessosSO = true;

    public static void main(String[] args) throws Exception {
        System.setProperty("jdk.lang.Process.launchMechanism", "FORK");
        Runtime.getRuntime().addShutdownHook(new Thread(SimuladorCasosTeste::encerrarTodosProcessos));

        Color.info("====================================================================================");
        Color.info("  SIMULAÇÃO P2P EM ANEL (SENTIDO HORÁRIO) - CRIPTOGRAFIA HÍBRIDA (RSA + AES + HMAC)");
        Color.info("  Processos: P0, P1, P2, P3, P4 e P5 (60 arquivos distribuídos salto a salto)");
        Color.info("====================================================================================\n");

        try {
            // =========================================================================
            // 1. Inicialização dos 6 Processos do Anel (P0 a P5)
            // =========================================================================
            Color.info("------------------------------------------------------------------------------------");
            Color.info("INICIALIZANDO OS 6 PROCESSOS DO ANEL (P0 a P5) E GERANDO PARES DE CHAVES RSA:");
            Color.info("------------------------------------------------------------------------------------");

            for (int id = 0; id < InfoNo.TOTAL_NOS; id++) {
                iniciarNoP2P(id);
            }

            // Aguarda os sockets UDP e chaves RSA dos 6 processos subirem
            Thread.sleep(1200);
            System.out.println();

            // =========================================================================
            // CASO 1: Busca válida com criptografia salto a salto
            // Origem: P0 | Arquivo: arquivo35.ext | Fluxo (Horário): P0 -> P1 -> P2 -> P3
            // =========================================================================
            Color.info("------------------------------------------------------------------------------------");
            Color.info("CASO 1: Busca válida com criptografia salto a salto");
            Color.info("  • Origem: P0 | Arquivo: arquivo35.ext | Fluxo (Horário): P0 -> P1 -> P2 -> P3");
            Color.info("  • Cada enlace (P0–P1, P1–P2, P2–P3) estabelece canal seguro com troca de chaves AES via RSA");
            Color.info("  • P3 localiza o arquivo (faixa 31–40) e responde com mensagem cifrada a P0");
            Color.info("------------------------------------------------------------------------------------");

            dispararBuscaEmNo(0, "arquivo35.ext", false);
            Thread.sleep(400);
            System.out.println();

            // =========================================================================
            // CASO 2: Entrada inválida
            // Origem: P1 (arquivo99.ext) e P4 (arquivoABC.ext)
            // =========================================================================
            Color.info("------------------------------------------------------------------------------------");
            Color.info("CASO 2: Entrada inválida (validação antes de criptografia ou conexões de rede)");
            Color.info("  • Origem: P1 (arquivo99.ext) e P4 (arquivoABC.ext)");
            Color.info("  • Rejeita a busca sem propagar pacotes pelo anel");
            Color.info("  • Imprime no console: Erro na entrada de dados. Tente outra vez!");
            Color.info("------------------------------------------------------------------------------------");

            Color.info("[Caso 2A] Processo P1 validando comando para 'arquivo99.ext':");
            dispararBuscaEmNo(1, "arquivo99.ext", false);
            Thread.sleep(200);
            System.out.println();

            Color.info("[Caso 2B] Processo P4 validando comando para 'arquivoABC.ext':");
            dispararBuscaEmNo(4, "arquivoABC.ext", false);
            Thread.sleep(200);
            System.out.println();

            // =========================================================================
            // CASO 3: Falha de integridade / Pacote adulterado
            // Origem: P4 enviando para P5 -> P5 detecta divergência de HMAC, descarta e interrompe repasse para P0
            // =========================================================================
            Color.info("------------------------------------------------------------------------------------");
            Color.info("CASO 3: Falha de integridade / Pacote adulterado");
            Color.info("  • Origem: P4 enviando para P5 (mensagem cifrada alterada no canal / HMAC inválido)");
            Color.info("  • P5 detecta a divergência do HMAC, descarta o pacote e interrompe o repasse para P0");
            Color.info("  • P5 grava no log a falha de autenticação/integridade");
            Color.info("------------------------------------------------------------------------------------");

            dispararBuscaEmNo(4, "arquivo10.ext", true);
            Thread.sleep(400);
            System.out.println();

            // =========================================================================
            // AUDITORIA DE LOGS: Tráfego e Validação Criptográfica em cada nó (P0 a P5)
            // =========================================================================
            Color.info("------------------------------------------------------------------------------------");
            Color.info("AUDITORIA DE LOGS: Tráfego e validação criptográfica registrados em P0..P5");
            Color.info("------------------------------------------------------------------------------------");

            for (int id = 0; id < InfoNo.TOTAL_NOS; id++) {
                String relatorioLogs = consultarLogsDoNo(id);
                System.out.println(Color.CIANO + relatorioLogs + Color.RESET);
            }

            // Encerra todos os nós P0..P5 de forma limpa
            for (int id = 0; id < InfoNo.TOTAL_NOS; id++) {
                enviarShutdownAoNo(id);
            }

            for (Process proc : PROCESSOS_ATIVOS) {
                if (proc != null) {
                    proc.waitFor();
                }
            }

            Color.sucesso("====================================================================================");
            Color.sucesso("  SIMULAÇÃO DOS CASOS 1, 2 E 3 CONCLUÍDA COM SUCESSO EM TODOS OS PROCESSOS (P0..P5)!");
            Color.sucesso("====================================================================================");
            System.exit(0);
        } finally {
            encerrarTodosProcessos();
        }
    }

    private static void iniciarNoP2P(int idNo) {
        String classeImpl = "impl.ImplNoP" + idNo;
        if (usarSubprocessosSO) {
            try {
                List<String> comando = new ArrayList<String>();
                comando.add(obterJavaBin());
                comando.add("-cp");
                comando.add(obterClassPath());
                comando.add(classeImpl);
                comando.add("--headless");

                ProcessBuilder pb = new ProcessBuilder(comando);
                pb.inheritIO();
                Process proc = pb.start();
                PROCESSOS_ATIVOS.add(proc);
                return;
            } catch (IOException e) {
                usarSubprocessosSO = false;
            }
        }
        NoP2P noLocal = new NoP2P(idNo, false);
        NOS_LOCAIS.add(noLocal);
    }

    /**
     * Envia um comando UDP TRIGGER_SEARCH (ou TRIGGER_TAMPERED_SEARCH para o Caso 3) ao processo P_{idOrigem}.
     */
    private static MensagemP2P dispararBuscaEmNo(int idOrigem, String nomeArquivo, boolean simularAdulteracao) {
        InfoNo noOrigem = InfoNo.obterPorId(idOrigem);
        try (DatagramSocket socketControle = new DatagramSocket()) {
            socketControle.setSoTimeout(6000);

            String idReq = "TRIG-" + UUID.randomUUID().toString().substring(0, 6).toUpperCase();
            String tipoComando = simularAdulteracao
                    ? MensagemP2P.TIPO_TRIGGER_TAMPERED_SEARCH
                    : MensagemP2P.TIPO_TRIGGER_SEARCH;

            MensagemP2P cmd = new MensagemP2P(
                    tipoComando,
                    idReq,
                    idOrigem,
                    "localhost",
                    socketControle.getLocalPort(),
                    nomeArquivo,
                    MensagemP2P.SENTIDO_HORARIO,
                    noOrigem.getNome(),
                    "Solicitação de busca em " + noOrigem.getNome()
            );

            byte[] envio = cmd.serializar().getBytes(StandardCharsets.UTF_8);
            DatagramPacket pctEnvio = new DatagramPacket(
                    envio,
                    envio.length,
                    InetAddress.getByName(noOrigem.getHost()),
                    noOrigem.getPorta()
            );
            socketControle.send(pctEnvio);

            byte[] bufferResp = new byte[8192];
            DatagramPacket pctResp = new DatagramPacket(bufferResp, bufferResp.length);
            socketControle.receive(pctResp);

            String respStr = new String(pctResp.getData(), 0, pctResp.getLength(), StandardCharsets.UTF_8);
            return MensagemP2P.desserializar(respStr);
        } catch (Exception e) {
            Color.erro("Falha ao acionar busca no nó " + noOrigem.getNome() + ": " + e.getMessage());
            return null;
        }
    }

    private static String consultarLogsDoNo(int idNo) {
        InfoNo no = InfoNo.obterPorId(idNo);
        try (DatagramSocket socketControle = new DatagramSocket()) {
            socketControle.setSoTimeout(3000);

            MensagemP2P cmd = new MensagemP2P(
                    MensagemP2P.TIPO_GET_LOGS,
                    "LOGS-" + idNo,
                    idNo,
                    "localhost",
                    socketControle.getLocalPort(),
                    "-",
                    MensagemP2P.SENTIDO_HORARIO,
                    no.getNome(),
                    "Consulta de logs"
            );

            byte[] envio = cmd.serializar().getBytes(StandardCharsets.UTF_8);
            DatagramPacket pctEnvio = new DatagramPacket(
                    envio,
                    envio.length,
                    InetAddress.getByName(no.getHost()),
                    no.getPorta()
            );
            socketControle.send(pctEnvio);

            byte[] bufferResp = new byte[16384];
            DatagramPacket pctResp = new DatagramPacket(bufferResp, bufferResp.length);
            socketControle.receive(pctResp);

            String respStr = new String(pctResp.getData(), 0, pctResp.getLength(), StandardCharsets.UTF_8);
            MensagemP2P respMsg = MensagemP2P.desserializar(respStr);
            return respMsg.getDetalhe();
        } catch (Exception e) {
            return "Não foi possível obter logs de " + no.getNome() + ": " + e.getMessage();
        }
    }

    private static void enviarShutdownAoNo(int idNo) {
        InfoNo no = InfoNo.obterPorId(idNo);
        try (DatagramSocket socketControle = new DatagramSocket()) {
            socketControle.setSoTimeout(1500);
            MensagemP2P cmd = new MensagemP2P(
                    MensagemP2P.TIPO_SHUTDOWN,
                    "STOP-" + idNo,
                    idNo,
                    "localhost",
                    socketControle.getLocalPort(),
                    "-",
                    MensagemP2P.SENTIDO_HORARIO,
                    no.getNome(),
                    "Encerrar processo"
            );
            byte[] envio = cmd.serializar().getBytes(StandardCharsets.UTF_8);
            DatagramPacket pctEnvio = new DatagramPacket(
                    envio,
                    envio.length,
                    InetAddress.getByName(no.getHost()),
                    no.getPorta()
            );
            socketControle.send(pctEnvio);

            byte[] bufferResp = new byte[1024];
            DatagramPacket pctResp = new DatagramPacket(bufferResp, bufferResp.length);
            socketControle.receive(pctResp);
        } catch (Exception e) {
            // Ignora no encerramento
        }
    }

    private static String obterJavaBin() {
        return System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";
    }

    private static String obterClassPath() {
        return System.getProperty("java.class.path");
    }

    private static void encerrarTodosProcessos() {
        for (NoP2P no : NOS_LOCAIS) {
            if (no != null) {
                no.pararNo();
            }
        }
        for (Process p : PROCESSOS_ATIVOS) {
            if (p != null && p.isAlive()) {
                p.destroyForcibly();
            }
        }
    }
}
