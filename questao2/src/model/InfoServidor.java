package model;

import java.util.List;

public class InfoServidor {
    private String nome;
    private String endereco;
    private int porta;
    private List<String> servicos;
    private boolean ativo;

    public InfoServidor(String nome, String endereco, int porta, List<String> servicos, boolean ativo) {
        this.nome = nome;
        this.endereco = endereco;
        this.porta = porta;
        this.servicos = servicos;
        this.ativo = ativo;
    }

    public String getNome() {
        return nome;
    }

    public String getendereco() {
        return endereco;
    }

    public int getPorta() {
        return porta;
    }

    public List<String> getServicos() {
        return servicos;
    }

    public boolean isAtivo() {
        return ativo;
    }

    public void setAtivo(boolean ativo) {
        this.ativo = ativo;
    }

    public boolean ofereceServico(String operacao) {
        String opNormalizada = normalizarOperacao(operacao);
        for (String s : servicos) {
            if (s.equalsIgnoreCase(opNormalizada) || s.equalsIgnoreCase(operacao.trim())) {
                return true;
            }
        }
        return false;
    }

    public static String normalizarOperacao(String entrada) {
        if (entrada == null) {
            return "";
        }
        String limpa = entrada.trim().toUpperCase()
                .replace("Á", "A").replace("Ã", "A").replace("Ç", "C").replace("Õ", "O");

        if (limpa.equals("SOMA") || limpa.equals("CALCULAR SOMA") || limpa.equals("+")) {
            return "SOMA";
        }
        if (limpa.equals("SUBTRACAO") || limpa.equals("CALCULAR SUBTRACAO") || limpa.equals("-")) {
            return "SUBTRACAO";
        }
        if (limpa.equals("MULTIPLICACAO") || limpa.equals("CALCULAR MULTIPLICACAO") || limpa.equals("*")) {
            return "MULTIPLICACAO";
        }
        if (limpa.equals("DIVISAO") || limpa.equals("CALCULAR DIVISAO") || limpa.equals("/")) {
            return "DIVISAO";
        }
        return limpa;
    }

    public static boolean isOperacaoValida(String entrada) {
        String op = normalizarOperacao(entrada);
        return op.equals("SOMA") || op.equals("SUBTRACAO")
                || op.equals("MULTIPLICACAO") || op.equals("DIVISAO");
    }

    public String getResumoEndereco() {
        return nome + "(" + endereco + ":" + porta + ")";
    }

    @Override
    public String toString() {
        String status = ativo ? "ATIVO" : "INATIVO";
        return nome + " | IP Simulado: " + endereco + " | Porta: " + porta
                + " | Status: " + status + " | Serviços: " + servicos;
    }
}
