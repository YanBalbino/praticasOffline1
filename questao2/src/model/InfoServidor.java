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
        for (String s : servicos) {
            if (s.equalsIgnoreCase(operacao.trim())) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String toString() {
        String status = ativo ? "ATIVO" : "INATIVO";
        return nome + " | IP Simulado: " + endereco + " | Porta: " + porta
                + " | Status: " + status + " | Serviços: " + servicos;
    }
}
