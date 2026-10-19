package no;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import log.Color;
import model.InfoNo;
import model.MensagemP2P;
import seguranca.CanalSeguroUDP;
import seguranca.CriptoUtils;
import seguranca.EnvelopeCriptografico;

/**
 * Nó P2P (Cliente/Servidor Multithread com UDP e Criptografia Híbrida Salto a Salto)
 * em uma topologia em anel (P0 a P5) com roteamento exclusivamente no sentido horário.
 *
 * Cada enlace (ex.: P0–P1, P1–P2, P2–P3, P3–P0) estabelece canal seguro com troca de chaves
 * AES/HMAC via RSA, encriptando, decifrando, verificando integridade (HMAC) e re-encriptando
 * salto a salto.
 */
public class NoP2P {

    private static final int TAMANHO_BUFFER_UDP = 16384;
    private static final long TIMEOUT_BUSCA_MS = 5000;
    private static final long TIMEOUT_BUSCA_ADULTERADA_MS = 1200;
    private static final DateTimeFormatter FORMATADOR_HORA = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    private final InfoNo infoAtual;
    private final InfoNo antecessor;
    private final InfoNo sucessor;
    private final Set<String> arquivosLocais;
    private final KeyPair parChavesRSA;

    private final List<String> historicoLogs;
    private final Map<String, CompletableFuture<MensagemP2P>> buscasPendentes;

    private DatagramSocket socketServidorUDP;
    private volatile boolean executando = true;

    public NoP2P(int idNo, boolean modoInterativo) {
        this.infoAtual = InfoNo.obterPorId(idNo);
        this.antecessor = InfoNo.obterAntecessor(idNo);
        this.sucessor = InfoNo.obterSucessor(idNo);
        this.arquivosLocais = Collections.synchronizedSet(infoAtual.gerarArquivosIniciais());
        this.parChavesRSA = CriptoUtils.gerarParChavesRSA();
        this.historicoLogs = new CopyOnWriteArrayList<String>();
        this.buscasPendentes = new ConcurrentHashMap<String, CompletableFuture<MensagemP2P>>();

        iniciarServidorUDP();

        if (modoInterativo) {
            rodarMenuInterativo();
        }
    }

    private void iniciarServidorUDP() {
        try {
            socketServidorUDP = new DatagramSocket(infoAtual.getPorta());
            long pid = ProcessHandle.current().pid();
            String pubKeyResumo = CriptoUtils.resumirBase64(CriptoUtils.chavePublicaParaBase64(parChavesRSA.getPublic()));

            Color.info("[" + infoAtual.getNome() + " | ID=" + infoAtual.getId() + " | PID=" + pid + "] "
                    + "Nó UDP ativo em " + infoAtual.getEnderecoSimulado() + " (porta real: " + infoAtual.getPorta() + ") "
                    + "| Sucessor (Horário): " + sucessor.getNome() + " (:" + sucessor.getPorta() + ") "
                    + "| RSA PubKey: " + pubKeyResumo + " "
                    + "| Arquivos: arquivo" + infoAtual.getArquivoInicial() + ".ext..arquivo" + infoAtual.getArquivoFinal() + ".ext");

            Thread threadEscuta = new Thread(this::loopRecebimentoUDP, "Thread-ServidorUDP-" + infoAtual.getNome());
            threadEscuta.start();
        } catch (IOException e) {
            Color.erro("[" + infoAtual.getNome() + "] Falha ao abrir DatagramSocket na porta "
                    + infoAtual.getPorta() + ": " + e.getMessage());
            executando = false;
        }
    }

    private void loopRecebimentoUDP() {
        while (executando && socketServidorUDP != null && !socketServidorUDP.isClosed()) {
            try {
                byte[] buffer = new byte[TAMANHO_BUFFER_UDP];
                DatagramPacket pacoteRecebido = new DatagramPacket(buffer, buffer.length);
                socketServidorUDP.receive(pacoteRecebido);

                final String payloadRecebido = new String(
                        pacoteRecebido.getData(),
                        0,
                        pacoteRecebido.getLength(),
                        StandardCharsets.UTF_8
                ).trim();
                final InetAddress enderecoRemetente = pacoteRecebido.getAddress();
                final int portaRemetente = pacoteRecebido.getPort();

                new Thread(
                        () -> processarPacoteRecebido(payloadRecebido, enderecoRemetente, portaRemetente),
                        "WorkerUDP-" + infoAtual.getNome() + "-" + System.nanoTime()
                ).start();

            } catch (IOException e) {
                if (executando) {
                    Color.erro("[" + infoAtual.getNome() + "] Erro ao receber pacote UDP: " + e.getMessage());
                }
            }
        }
    }

    private void processarPacoteRecebido(String payloadBruto, InetAddress enderecoRemetente, int portaRemetente) {
        // 1. Atendimento ao Handshake RSA salto a salto (envio da Chave Pública RSA do nó atual)
        if (payloadBruto.startsWith(CanalSeguroUDP.PREFIXO_HANDSHAKE_REQ)) {
            tratarHandshakeRSA(payloadBruto, enderecoRemetente, portaRemetente);
            return;
        }

        // 2. Abertura e validação do Envelope Criptográfico Híbrido (AES + HMAC + RSA)
        String payloadDecifrado = payloadBruto;
        if (payloadBruto.startsWith("ENVELOPE|")) {
            try {
                EnvelopeCriptografico envelope = EnvelopeCriptografico.abrirEValidarEnvelope(
                        payloadBruto,
                        infoAtual.getNome(),
                        parChavesRSA.getPrivate()
                );
                payloadDecifrado = envelope.getMensagemOriginal();
                registrarLogSeguranca("Canal seguro validado no enlace " + envelope.getNomeEmissor() + "–" + infoAtual.getNome()
                        + " | AES decifrado e integridade HMAC verificada (" + CriptoUtils.resumirBase64(envelope.getHashHmacValido()) + ")");
            } catch (SecurityException se) {
                // Caso 3: Falha de integridade / Pacote adulterado -> Registra no log, descarta pacote e interrompe repasse
                registrarLogFalhaSeguranca("FALHA DE AUTENTICAÇÃO/INTEGRIDADE detectada em " + infoAtual.getNome()
                        + ": " + se.getMessage() + " -> Pacote descartado e repasse interrompido!");
                return;
            }
        }

        MensagemP2P msg;
        try {
            msg = MensagemP2P.desserializar(payloadDecifrado);
        } catch (IllegalArgumentException ex) {
            registrarLogRecebido("ORIGEM=" + enderecoRemetente.getHostAddress() + ":" + portaRemetente
                    + " | PAYLOAD_INVALIDO=\"" + payloadDecifrado + "\"");
            Color.erro("[" + infoAtual.getNome() + "] " + MensagemP2P.MSG_ERRO_ENTRADA);
            return;
        }

        if (!MensagemP2P.TIPO_TRIGGER_SEARCH.equals(msg.getTipo())
                && !MensagemP2P.TIPO_TRIGGER_TAMPERED_SEARCH.equals(msg.getTipo())
                && !MensagemP2P.TIPO_GET_LOGS.equals(msg.getTipo())
                && !MensagemP2P.TIPO_SHUTDOWN.equals(msg.getTipo())) {
            registrarLogRecebido("De " + enderecoRemetente.getHostAddress() + ":" + portaRemetente
                    + " -> " + msg.toString());
        }

        switch (msg.getTipo()) {
            case MensagemP2P.TIPO_SEARCH:
                tratarMensagemSearch(msg);
                break;

            case MensagemP2P.TIPO_FOUND:
                tratarMensagemFound(msg);
                break;

            case MensagemP2P.TIPO_NOT_FOUND:
                tratarMensagemNotFound(msg);
                break;

            case MensagemP2P.TIPO_TRIGGER_SEARCH:
                tratarComandoTriggerSearch(msg, enderecoRemetente, portaRemetente, false);
                break;

            case MensagemP2P.TIPO_TRIGGER_TAMPERED_SEARCH:
                tratarComandoTriggerSearch(msg, enderecoRemetente, portaRemetente, true);
                break;

            case MensagemP2P.TIPO_GET_LOGS:
                tratarComandoGetLogs(msg, enderecoRemetente, portaRemetente);
                break;

            case MensagemP2P.TIPO_SHUTDOWN:
                tratarComandoShutdown(msg, enderecoRemetente, portaRemetente);
                break;

            default:
                Color.erro("[" + infoAtual.getNome() + "] " + MensagemP2P.MSG_ERRO_ENTRADA);
                break;
        }
    }

    private void tratarHandshakeRSA(String payloadBruto, InetAddress enderecoRemetente, int portaRemetente) {
        String[] partes = payloadBruto.split("\\|");
        String nomeEmissor = partes.length >= 2 ? partes[1].trim() : "DESCONHECIDO";
        String pubKeyLocalB64 = CriptoUtils.chavePublicaParaBase64(parChavesRSA.getPublic());
        String resposta = CanalSeguroUDP.PREFIXO_HANDSHAKE_RESP + infoAtual.getNome() + "|" + pubKeyLocalB64;

        registrarLogSeguranca("Handshake RSA no enlace " + nomeEmissor + "–" + infoAtual.getNome()
                + ": Chave Pública RSA de " + infoAtual.getNome() + " enviada a " + nomeEmissor);
        enviarDatagramaBruto(resposta, enderecoRemetente.getHostAddress(), portaRemetente);
    }

    private void tratarMensagemSearch(MensagemP2P msg) {
        String arquivoBuscado = msg.getNomeArquivo();
        String rotaAtualizada = msg.getRota().isEmpty()
                ? infoAtual.getNome()
                : msg.getRota() + " -> " + infoAtual.getNome();

        if (possuiArquivo(arquivoBuscado)) {
            String detalheEncontrado = "Arquivo '" + arquivoBuscado + "' localizado no processo "
                    + infoAtual.getNome() + " (faixa " + infoAtual.getArquivoInicial()
                    + "–" + infoAtual.getArquivoFinal() + ", Endereço=" + infoAtual.getEnderecoSimulado()
                    + ":" + infoAtual.getPorta() + ")";

            Color.sucesso("[" + infoAtual.getNome() + "] Recurso '" + arquivoBuscado
                    + "' ENCONTRADO localmente (faixa " + infoAtual.getArquivoInicial() + "–" + infoAtual.getArquivoFinal()
                    + ")! Respondendo com mensagem cifrada para P" + msg.getIdOrigem()
                    + " (Fluxo: " + rotaAtualizada + ")");

            MensagemP2P respostaFound = new MensagemP2P(
                    MensagemP2P.TIPO_FOUND,
                    msg.getIdMensagem(),
                    infoAtual.getId(),
                    infoAtual.getHost(),
                    infoAtual.getPorta(),
                    arquivoBuscado,
                    MensagemP2P.SENTIDO_HORARIO,
                    rotaAtualizada,
                    detalheEncontrado
            );

            enviarMensagemSeguraUDP(respostaFound, msg.getHostOrigem(), msg.getPortaResposta(), "P" + msg.getIdOrigem(), false);
            return;
        }

        // Roteamento exclusivamente no sentido HORÁRIO (sempre para o sucessor)
        InfoNo proximoNo = sucessor;

        if (proximoNo.getId() == msg.getIdOrigem()) {
            String detalheNaoEncontrado = "Arquivo '" + arquivoBuscado
                    + "' não foi encontrado em nenhum dos 6 nós do anel (P0..P5).";

            Color.alerta("[" + infoAtual.getNome() + "] Busca por '" + arquivoBuscado
                    + "' completou a volta no anel (" + rotaAtualizada + ") sem sucesso. Notificando P"
                    + msg.getIdOrigem() + ".");

            MensagemP2P respostaNotFound = new MensagemP2P(
                    MensagemP2P.TIPO_NOT_FOUND,
                    msg.getIdMensagem(),
                    infoAtual.getId(),
                    infoAtual.getHost(),
                    infoAtual.getPorta(),
                    arquivoBuscado,
                    MensagemP2P.SENTIDO_HORARIO,
                    rotaAtualizada,
                    detalheNaoEncontrado
            );

            enviarMensagemSeguraUDP(respostaNotFound, msg.getHostOrigem(), msg.getPortaResposta(), "P" + msg.getIdOrigem(), false);
            return;
        }

        String detalheRepasse = "Repassado no sentido HORÁRIO por " + infoAtual.getNome() + " para " + proximoNo.getNome();
        Color.info("[" + infoAtual.getNome() + "] Arquivo '" + arquivoBuscado
                + "' não encontrado localmente em " + infoAtual.getNome()
                + ". Re-encriptando e repassando ao sucessor " + proximoNo.getNome() + " (:" + proximoNo.getPorta() + ")...");

        MensagemP2P msgRepasse = msg.comNovaRota(rotaAtualizada, detalheRepasse);
        enviarMensagemSeguraUDP(msgRepasse, proximoNo.getHost(), proximoNo.getPorta(), proximoNo.getNome(), false);
    }

    private void tratarMensagemFound(MensagemP2P msg) {
        Color.sucesso(">>> [" + infoAtual.getNome() + " - BUSCA CONCLUÍDA] " + msg.getDetalhe()
                + " | Fluxo (Horário): [" + msg.getRota() + "]");

        CompletableFuture<MensagemP2P> future = buscasPendentes.remove(msg.getIdMensagem());
        if (future != null) {
            future.complete(msg);
        }
    }

    private void tratarMensagemNotFound(MensagemP2P msg) {
        Color.alerta(">>> [" + infoAtual.getNome() + " - ARQUIVO NÃO ENCONTRADO] " + msg.getDetalhe()
                + " | Caminho percorrido: [" + msg.getRota() + "]");

        CompletableFuture<MensagemP2P> future = buscasPendentes.remove(msg.getIdMensagem());
        if (future != null) {
            future.complete(msg);
        }
    }

    private void tratarComandoTriggerSearch(
            MensagemP2P msg,
            InetAddress enderecoCliente,
            int portaCliente,
            boolean simularAdulteracao) {
        MensagemP2P resultado = iniciarBuscaNoAnel(msg.getNomeArquivo(), simularAdulteracao);
        enviarDatagramaBruto(resultado.serializar(), enderecoCliente.getHostAddress(), portaCliente);
    }

    private void tratarComandoGetLogs(MensagemP2P msg, InetAddress enderecoCliente, int portaCliente) {
        StringBuilder sb = new StringBuilder();
        sb.append("Histórico de Logs do Processo ").append(infoAtual.getNome())
          .append(" (ID=").append(infoAtual.getId()).append(", Total=").append(historicoLogs.size()).append("):\n");
        if (historicoLogs.isEmpty()) {
            sb.append("  (Nenhuma mensagem registrada)\n");
        } else {
            for (String item : historicoLogs) {
                sb.append("  - ").append(item).append("\n");
            }
        }
        MensagemP2P resp = new MensagemP2P(
                MensagemP2P.TIPO_LOGS_RESPONSE,
                msg.getIdMensagem(),
                infoAtual.getId(),
                infoAtual.getHost(),
                infoAtual.getPorta(),
                "-",
                MensagemP2P.SENTIDO_HORARIO,
                infoAtual.getNome(),
                sb.toString()
        );
        enviarDatagramaBruto(resp.serializar(), enderecoCliente.getHostAddress(), portaCliente);
    }

    private void tratarComandoShutdown(MensagemP2P msg, InetAddress enderecoCliente, int portaCliente) {
        MensagemP2P ack = new MensagemP2P(
                MensagemP2P.TIPO_ACK,
                msg.getIdMensagem(),
                infoAtual.getId(),
                infoAtual.getHost(),
                infoAtual.getPorta(),
                "-",
                MensagemP2P.SENTIDO_HORARIO,
                infoAtual.getNome(),
                "Encerrando " + infoAtual.getNome()
        );
        enviarDatagramaBruto(ack.serializar(), enderecoCliente.getHostAddress(), portaCliente);
        pararNo();
    }

    /**
     * Inicia uma busca no anel sempre no sentido HORÁRIO (sucessor).
     */
    public MensagemP2P iniciarBuscaNoAnel(String entradaArquivo) {
        return iniciarBuscaNoAnel(entradaArquivo, false);
    }

    /**
     * Inicia uma busca no anel no sentido HORÁRIO, permitindo simular adulteração de pacote/HMAC (Caso 3).
     * Caso 2: Valida a entrada ANTES de iniciar criptografia ou abrir conexões de rede.
     */
    public MensagemP2P iniciarBuscaNoAnel(String entradaArquivo, boolean simularFalhaIntegridade) {
        // Caso 2: Validação estrita antes de qualquer operação criptográfica ou de rede
        if (!MensagemP2P.isNomeArquivoValido(entradaArquivo)) {
            System.out.println(MensagemP2P.MSG_ERRO_ENTRADA);
            Color.erro("[" + infoAtual.getNome() + "] Entrada inválida ('" + entradaArquivo
                    + "') rejeitada antes de iniciar criptografia ou conexões de rede.");
            registrarLogSeguranca("Comando inválido ('" + entradaArquivo + "') rejeitado localmente em "
                    + infoAtual.getNome() + " sem propagar pacotes pelo anel.");
            return new MensagemP2P(
                    "ERRO_ENTRADA",
                    "INVALIDO",
                    infoAtual.getId(),
                    infoAtual.getHost(),
                    infoAtual.getPorta(),
                    String.valueOf(entradaArquivo),
                    MensagemP2P.SENTIDO_HORARIO,
                    infoAtual.getNome(),
                    MensagemP2P.MSG_ERRO_ENTRADA
            );
        }

        String arquivoNormalizado = MensagemP2P.normalizarNomeArquivo(entradaArquivo);
        String idMsg = "MSG-" + infoAtual.getNome() + "-" + UUID.randomUUID().toString().substring(0, 6).toUpperCase();

        if (!simularFalhaIntegridade && possuiArquivo(arquivoNormalizado)) {
            String detalheLocal = "Arquivo '" + arquivoNormalizado + "' já se encontra localmente em "
                    + infoAtual.getNome() + " (faixa " + infoAtual.getArquivoInicial() + "–" + infoAtual.getArquivoFinal() + ")";
            registrarLogEnviado("Busca local em " + infoAtual.getNome() + " pelo recurso '" + arquivoNormalizado + "' (resolvido sem repasse externo)");
            Color.sucesso(">>> [" + infoAtual.getNome() + " - BUSCA LOCAL] " + detalheLocal
                    + " | Caminho no anel: [" + infoAtual.getNome() + "]");

            return new MensagemP2P(
                    MensagemP2P.TIPO_FOUND,
                    idMsg,
                    infoAtual.getId(),
                    infoAtual.getHost(),
                    infoAtual.getPorta(),
                    arquivoNormalizado,
                    MensagemP2P.SENTIDO_HORARIO,
                    infoAtual.getNome(),
                    detalheLocal
            );
        }

        // Busca percorre exclusivamente no sentido horário (sucessor)
        InfoNo primeiroSalto = sucessor;

        MensagemP2P msgBusca = new MensagemP2P(
                MensagemP2P.TIPO_SEARCH,
                idMsg,
                infoAtual.getId(),
                infoAtual.getHost(),
                infoAtual.getPorta(),
                arquivoNormalizado,
                MensagemP2P.SENTIDO_HORARIO,
                infoAtual.getNome(),
                "Busca iniciada por " + infoAtual.getNome() + " (HORARIO)"
        );

        CompletableFuture<MensagemP2P> futureResposta = new CompletableFuture<MensagemP2P>();
        buscasPendentes.put(idMsg, futureResposta);

        Color.info("[" + infoAtual.getNome() + "] Iniciando busca pelo recurso '" + arquivoNormalizado
                + "' no sentido HORÁRIO -> estabelecendo canal seguro com sucessor "
                + primeiroSalto.getNome() + " (:" + primeiroSalto.getPorta() + ")...");

        enviarMensagemSeguraUDP(
                msgBusca,
                primeiroSalto.getHost(),
                primeiroSalto.getPorta(),
                primeiroSalto.getNome(),
                simularFalhaIntegridade
        );

        long timeout = simularFalhaIntegridade ? TIMEOUT_BUSCA_ADULTERADA_MS : TIMEOUT_BUSCA_MS;
        try {
            return futureResposta.get(timeout, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            buscasPendentes.remove(idMsg);
            String msgTimeout = simularFalhaIntegridade
                    ? "Busca interrompida no enlace " + infoAtual.getNome() + "–" + primeiroSalto.getNome()
                            + " devido ao descarte do pacote adulterado por falha de integridade (HMAC inválido)."
                    : "Tempo limite excedido aguardando resposta do anel para '" + arquivoNormalizado
                            + "'. Verifique se todos os nós P0..P5 estão ativos.";
            if (simularFalhaIntegridade) {
                Color.alerta("[" + infoAtual.getNome() + "] " + msgTimeout);
            } else {
                Color.erro("[" + infoAtual.getNome() + "] " + msgTimeout);
            }
            return new MensagemP2P(
                    MensagemP2P.TIPO_NOT_FOUND,
                    idMsg,
                    infoAtual.getId(),
                    infoAtual.getHost(),
                    infoAtual.getPorta(),
                    arquivoNormalizado,
                    MensagemP2P.SENTIDO_HORARIO,
                    infoAtual.getNome(),
                    msgTimeout
            );
        }
    }

    /**
     * Estabelece o canal seguro salto a salto (Handshake RSA + chave de sessão AES/HMAC) e envia o
     * Envelope Criptográfico via UDP ao próximo nó.
     */
    private void enviarMensagemSeguraUDP(
            MensagemP2P mensagem,
            String hostDestino,
            int portaDestino,
            String nomeNoDestino,
            boolean simularFalhaIntegridade) {

        String payloadPlano = mensagem.serializar();
        try {
            CanalSeguroUDP.ResultadoEnvioSeguro resultado = CanalSeguroUDP.estabelecerCanalEPrepararEnvelope(
                    infoAtual.getNome(),
                    parChavesRSA,
                    hostDestino,
                    portaDestino,
                    nomeNoDestino,
                    payloadPlano,
                    simularFalhaIntegridade
            );

            registrarLogSeguranca(resultado.getResumoHandshake());
            registrarLogEnviado("Para " + nomeNoDestino + " (" + hostDestino + ":" + portaDestino + ") [CIFRADO AES/HMAC] -> " + mensagem.toString());
            enviarDatagramaBruto(resultado.getEnvelopeSerializado(), hostDestino, portaDestino);
        } catch (Exception e) {
            Color.erro("[" + infoAtual.getNome() + "] Falha de segurança/rede ao enviar pacote para "
                    + nomeNoDestino + ": " + e.getMessage());
        }
    }

    private void enviarDatagramaBruto(String payload, String hostDestino, int portaDestino) {
        try {
            byte[] dados = payload.getBytes(StandardCharsets.UTF_8);
            InetAddress endereco = InetAddress.getByName(hostDestino);
            DatagramPacket pacote = new DatagramPacket(dados, dados.length, endereco, portaDestino);
            socketServidorUDP.send(pacote);
        } catch (IOException e) {
            Color.erro("[" + infoAtual.getNome() + "] Erro ao enviar datagrama UDP para "
                    + hostDestino + ":" + portaDestino + ": " + e.getMessage());
        }
    }

    private void registrarLogEnviado(String descricao) {
        String entrada = "[" + LocalTime.now().format(FORMATADOR_HORA) + "] [" + infoAtual.getNome() + " - ENVIADO] " + descricao;
        historicoLogs.add(entrada);
        Color.enviado("[" + infoAtual.getNome() + "] " + descricao);
    }

    private void registrarLogRecebido(String descricao) {
        String entrada = "[" + LocalTime.now().format(FORMATADOR_HORA) + "] [" + infoAtual.getNome() + " - RECEBIDO] " + descricao;
        historicoLogs.add(entrada);
        Color.recebido("[" + infoAtual.getNome() + "] " + descricao);
    }

    private void registrarLogSeguranca(String descricao) {
        String entrada = "[" + LocalTime.now().format(FORMATADOR_HORA) + "] [" + infoAtual.getNome() + " - CRIPTO] " + descricao;
        historicoLogs.add(entrada);
    }

    private void registrarLogFalhaSeguranca(String descricao) {
        String entrada = "[" + LocalTime.now().format(FORMATADOR_HORA) + "] [" + infoAtual.getNome() + " - FALHA-HMAC] " + descricao;
        historicoLogs.add(entrada);
    }

    public boolean possuiArquivo(String nomeArquivo) {
        if (nomeArquivo == null) {
            return false;
        }
        String normalizado = MensagemP2P.normalizarNomeArquivo(nomeArquivo);
        return normalizado != null && arquivosLocais.contains(normalizado);
    }

    public void imprimirInformacoesDoNo() {
        System.out.println(Color.CIANO_BRILHANTE + "---------------------------------------------------------" + Color.RESET);
        System.out.println(Color.NEGRITO + "INFORMAÇÕES DO NÓ " + infoAtual.getNome() + ":" + Color.RESET);
        System.out.println("  • Identificador Numérico : " + infoAtual.getId());
        System.out.println("  • Nome Simbólico         : " + infoAtual.getNome());
        System.out.println("  • Endereço Simulado      : " + infoAtual.getEnderecoSimulado() + " (UDP real: " + infoAtual.getHost() + ":" + infoAtual.getPorta() + ")");
        System.out.println("  • Nó Antecessor          : " + antecessor.getResumoCurto());
        System.out.println("  • Nó Sucessor (Horário)  : " + sucessor.getResumoCurto());
        System.out.println("  • Chave Pública RSA      : " + CriptoUtils.resumirBase64(CriptoUtils.chavePublicaParaBase64(parChavesRSA.getPublic())));
        System.out.println("  • Arquivos Locais (10)   : " + arquivosLocais);
        System.out.println(Color.CIANO_BRILHANTE + "---------------------------------------------------------" + Color.RESET);
    }

    public void imprimirHistoricoLogs() {
        System.out.println(Color.CIANO_BRILHANTE + "---------------------------------------------------------" + Color.RESET);
        System.out.println(Color.NEGRITO + "LOG DE TRÁFEGO E VALIDAÇÃO CRIPTOGRÁFICA (" + infoAtual.getNome()
                + " - Total: " + historicoLogs.size() + "):" + Color.RESET);
        if (historicoLogs.isEmpty()) {
            System.out.println("  (Nenhuma mensagem registrada até o momento)");
        } else {
            for (String log : historicoLogs) {
                System.out.println("  " + log);
            }
        }
        System.out.println(Color.CIANO_BRILHANTE + "---------------------------------------------------------" + Color.RESET);
    }

    /**
     * Menu interativo no console para operar qualquer nó (P0 a P5) com busca exclusivamente no sentido horário.
     */
    private void rodarMenuInterativo() {
        @SuppressWarnings("resource")
        Scanner teclado = new Scanner(System.in);

        while (executando) {
            exibirMenu();
            if (!teclado.hasNextLine()) {
                break;
            }
            String opcao = teclado.nextLine().trim();

            switch (opcao) {
                case "0":
                    imprimirInformacoesDoNo();
                    break;

                case "1":
                    System.out.print("Digite o nome do arquivo a buscar (ex: arquivo35.ext): ");
                    if (!teclado.hasNextLine()) {
                        return;
                    }
                    String arqHorario = teclado.nextLine().trim();
                    iniciarBuscaNoAnel(arqHorario, false);
                    System.out.println();
                    break;

                case "2":
                    System.out.print("Digite o nome do arquivo para simular envio com pacote/HMAC adulterado ao sucessor "
                            + sucessor.getNome() + " (ex: arquivo10.ext): ");
                    if (!teclado.hasNextLine()) {
                        return;
                    }
                    String arqAdulterado = teclado.nextLine().trim();
                    iniciarBuscaNoAnel(arqAdulterado, true);
                    System.out.println();
                    break;

                case "3":
                    imprimirHistoricoLogs();
                    break;

                case "4":
                    Color.info("[" + infoAtual.getNome() + "] Encerrando nó P2P...");
                    pararNo();
                    return;

                default:
                    System.out.println(MensagemP2P.MSG_ERRO_ENTRADA);
                    break;
            }
        }
    }

    private void exibirMenu() {
        System.out.println(Color.CIANO_BRILHANTE + "=========================================================" + Color.RESET);
        System.out.println(Color.NEGRITO + "NÓ P2P EM ANEL (SEGURANÇA HÍBRIDA RSA+AES+HMAC): " + infoAtual.getNome()
                + " (ID=" + infoAtual.getId()
                + " | Sucessor Horário=" + sucessor.getNome() + ")" + Color.RESET);
        System.out.println(
                "0 - Exibir informações do nó (ID, chave pública RSA, sucessor e arquivos locais)\n" +
                "1 - Buscar arquivo no anel (Sentido Horário -> cifra com AES/HMAC para " + sucessor.getNome() + ")\n" +
                "2 - Simular busca com falha de integridade / HMAC adulterado (Caso 3 -> " + sucessor.getNome() + ")\n" +
                "3 - Exibir log de tráfego e validação criptográfica\n" +
                "4 - Encerrar nó"
        );
        System.out.print("Selecione uma operação: ");
        System.out.flush();
    }

    public void pararNo() {
        executando = false;
        if (socketServidorUDP != null && !socketServidorUDP.isClosed()) {
            socketServidorUDP.close();
            Color.alerta("[" + infoAtual.getNome() + "] Socket UDP fechado.");
        }
    }

    public InfoNo getInfoAtual() {
        return infoAtual;
    }

    public List<String> getHistoricoLogs() {
        return Collections.unmodifiableList(historicoLogs);
    }

    public static void main(String[] args) {
        int id = 0;
        boolean interativo = true;

        if (args.length >= 1) {
            try {
                String argId = args[0].trim().toUpperCase().replace("P", "");
                id = Integer.parseInt(argId);
                if (id < 0 || id >= InfoNo.TOTAL_NOS) {
                    System.out.println(MensagemP2P.MSG_ERRO_ENTRADA);
                    return;
                }
            } catch (NumberFormatException e) {
                System.out.println(MensagemP2P.MSG_ERRO_ENTRADA);
                return;
            }
        }

        if (args.length >= 2 && args[1].equalsIgnoreCase("--headless")) {
            interativo = false;
        }

        new NoP2P(id, interativo);
    }
}
