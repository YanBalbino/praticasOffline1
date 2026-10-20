package model;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MensagemP2P {

    public static final String TIPO_SEARCH = "SEARCH";
    public static final String TIPO_FOUND = "FOUND";
    public static final String TIPO_NOT_FOUND = "NOT_FOUND";
    public static final String TIPO_TRIGGER_SEARCH = "TRIGGER_SEARCH";
    public static final String TIPO_TRIGGER_TAMPERED_SEARCH = "TRIGGER_TAMPERED_SEARCH";
    public static final String TIPO_GET_LOGS = "GET_LOGS";
    public static final String TIPO_LOGS_RESPONSE = "LOGS_RESPONSE";
    public static final String TIPO_SHUTDOWN = "SHUTDOWN";
    public static final String TIPO_ACK = "ACK";

    public static final String SENTIDO_HORARIO = "HORARIO";
    public static final int MIN_ARQUIVO = 1;
    public static final int MAX_ARQUIVO = InfoNo.TOTAL_NOS * InfoNo.ARQUIVOS_POR_NO; // 60

    public static final String MSG_ERRO_ENTRADA = "Erro na entrada de dados. Tente outra vez!";

    private static final Pattern PADRAO_ARQUIVO = Pattern.compile("^arquivo([1-9][0-9]*)(?:\\.ext)?$", Pattern.CASE_INSENSITIVE);

    private final String tipo;
    private final String idMensagem;
    private final int idOrigem;
    private final String hostOrigem;
    private final int portaResposta;
    private final String nomeArquivo;
    private final String sentido;
    private final String rota;
    private final String detalhe;

    public MensagemP2P(
            String tipo,
            String idMensagem,
            int idOrigem,
            String hostOrigem,
            int portaResposta,
            String nomeArquivo,
            String sentido,
            String rota,
            String detalhe) {
        this.tipo = tipo != null ? tipo.trim() : "";
        this.idMensagem = idMensagem != null ? idMensagem.trim() : "";
        this.idOrigem = idOrigem;
        this.hostOrigem = hostOrigem != null ? hostOrigem.trim() : "localhost";
        this.portaResposta = portaResposta;
        this.nomeArquivo = nomeArquivo != null ? nomeArquivo.trim() : "";
        this.sentido = (sentido != null && !sentido.trim().isEmpty()) ? sentido.trim().toUpperCase() : SENTIDO_HORARIO;
        this.rota = rota != null ? rota.trim() : "";
        this.detalhe = detalhe != null ? detalhe.trim() : "";
    }

    public String getTipo() {
        return tipo;
    }

    public String getIdMensagem() {
        return idMensagem;
    }

    public int getIdOrigem() {
        return idOrigem;
    }

    public String getHostOrigem() {
        return hostOrigem;
    }

    public int getPortaResposta() {
        return portaResposta;
    }

    public String getNomeArquivo() {
        return nomeArquivo;
    }

    public String getSentido() {
        return sentido;
    }

    public String getRota() {
        return rota;
    }

    public String getDetalhe() {
        return detalhe;
    }

    public MensagemP2P comNovaRota(String novaRota, String novoDetalhe) {
        return new MensagemP2P(
                this.tipo,
                this.idMensagem,
                this.idOrigem,
                this.hostOrigem,
                this.portaResposta,
                this.nomeArquivo,
                this.sentido,
                novaRota,
                novoDetalhe
        );
    }

    public String serializar() {
        String detalheSeguro = detalhe.replace("|", "/").replace("\n", "\\n");
        return tipo + "|"
                + idMensagem + "|"
                + idOrigem + "|"
                + hostOrigem + "|"
                + portaResposta + "|"
                + nomeArquivo + "|"
                + sentido + "|"
                + rota + "|"
                + detalheSeguro;
    }

    public static MensagemP2P desserializar(String bruto) {
        if (bruto == null || bruto.trim().isEmpty()) {
            throw new IllegalArgumentException(MSG_ERRO_ENTRADA);
        }
        String[] partes = bruto.trim().split("\\|", -1);
        if (partes.length < 9) {
            throw new IllegalArgumentException(MSG_ERRO_ENTRADA);
        }
        try {
            String tipo = partes[0].trim();
            String idMensagem = partes[1].trim();
            int idOrigem = Integer.parseInt(partes[2].trim());
            String hostOrigem = partes[3].trim();
            int portaResposta = Integer.parseInt(partes[4].trim());
            String nomeArquivo = partes[5].trim();
            String sentido = partes[6].trim();
            String rota = partes[7].trim();
            String detalhe = partes[8].trim().replace("\\n", "\n");

            return new MensagemP2P(
                    tipo,
                    idMensagem,
                    idOrigem,
                    hostOrigem,
                    portaResposta,
                    nomeArquivo,
                    sentido,
                    rota,
                    detalhe
            );
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(MSG_ERRO_ENTRADA, e);
        }
    }

    public static boolean isNomeArquivoValido(String entrada) {
        return normalizarNomeArquivo(entrada) != null;
    }

    public static String normalizarNomeArquivo(String entrada) {
        if (entrada == null || entrada.trim().isEmpty()) {
            return null;
        }
        Matcher m = PADRAO_ARQUIVO.matcher(entrada.trim());
        if (!m.matches()) {
            return null;
        }
        try {
            int numero = Integer.parseInt(m.group(1));
            if (numero < MIN_ARQUIVO || numero > MAX_ARQUIVO) {
                return null;
            }
            return "arquivo" + numero + ".ext";
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public static String normalizarSentido(String entrada) {
        if (entrada == null || entrada.trim().isEmpty()) {
            return SENTIDO_HORARIO;
        }
        String limpa = entrada.trim().toUpperCase()
                .replace("Á", "A")
                .replace("-", "_");
        if (limpa.equals("HORARIO") || limpa.equals("H") || limpa.equals("SUCESSOR") || limpa.equals("1")) {
            return SENTIDO_HORARIO;
        }
        return null;
    }

    @Override
    public String toString() {
        return "[" + tipo + "; id=" + idMensagem + "; origem=P" + idOrigem
                + "; arquivo=" + nomeArquivo + "; sentido=" + sentido
                + "; rota=" + rota + "; info=" + detalhe + "]";
    }
}
