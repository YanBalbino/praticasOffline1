package model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Representa os metadados e a configuração de um nó (processo) na topologia em anel P2P.
 * Considere 6 processos: P0, P1, P2, P3, P4 e P5.
 */
public class InfoNo {
    public static final int TOTAL_NOS = 6;
    public static final int PORTA_BASE = 8000;
    public static final int ARQUIVOS_POR_NO = 10;

    private final int id;
    private final String nome;
    private final String enderecoSimulado;
    private final String host;
    private final int porta;
    private final int arquivoInicial;
    private final int arquivoFinal;

    public InfoNo(int id, String host, int porta) {
        if (id < 0 || id >= TOTAL_NOS) {
            throw new IllegalArgumentException("O identificador do nó deve estar entre 0 e " + (TOTAL_NOS - 1));
        }
        this.id = id;
        this.nome = "P" + id;
        this.enderecoSimulado = "192.168.0." + (100 + id);
        this.host = host;
        this.porta = porta;
        this.arquivoInicial = (id * ARQUIVOS_POR_NO) + 1;
        this.arquivoFinal = (id + 1) * ARQUIVOS_POR_NO;
    }

    public int getId() {
        return id;
    }

    public String getNome() {
        return nome;
    }

    public String getEnderecoSimulado() {
        return enderecoSimulado;
    }

    public String getHost() {
        return host;
    }

    public int getPorta() {
        return porta;
    }

    public int getArquivoInicial() {
        return arquivoInicial;
    }

    public int getArquivoFinal() {
        return arquivoFinal;
    }

    public Set<String> gerarArquivosIniciais() {
        Set<String> arquivos = new LinkedHashSet<String>();
        for (int i = arquivoInicial; i <= arquivoFinal; i++) {
            arquivos.add("arquivo" + i + ".ext");
        }
        return arquivos;
    }

    public static InfoNo obterPorId(int id) {
        int idNormalizado = ((id % TOTAL_NOS) + TOTAL_NOS) % TOTAL_NOS;
        return new InfoNo(idNormalizado, "localhost", PORTA_BASE + idNormalizado);
    }

    public static InfoNo obterSucessor(int idAtual) {
        return obterPorId((idAtual + 1) % TOTAL_NOS);
    }

    public static InfoNo obterAntecessor(int idAtual) {
        return obterPorId((idAtual - 1 + TOTAL_NOS) % TOTAL_NOS);
    }

    public static List<InfoNo> obterTodosOsNos() {
        List<InfoNo> lista = new ArrayList<InfoNo>(TOTAL_NOS);
        for (int i = 0; i < TOTAL_NOS; i++) {
            lista.add(obterPorId(i));
        }
        return Collections.unmodifiableList(lista);
    }

    public String getResumoCurto() {
        return nome + " (ID=" + id + ", " + enderecoSimulado + ":" + porta + ")";
    }

    @Override
    public String toString() {
        return nome + " [ID=" + id + " | IP Simulado: " + enderecoSimulado
                + " | UDP: " + host + ":" + porta
                + " | Arquivos: arquivo" + arquivoInicial + ".ext .. arquivo" + arquivoFinal + ".ext]";
    }
}
