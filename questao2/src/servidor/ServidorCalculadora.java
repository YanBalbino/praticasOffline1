package servidor;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import diretorio.ServidorDiretorio;

public class ServidorCalculadora {
    private String nome;
    private String endereco;
    private int porta;
    private String hostDiretorio;
    private int portaDiretorio;

    public ServidorCalculadora(String nome, String endereco, int porta, String hostDiretorio, int portaDiretorio) {
        this.nome = nome;
        this.endereco = endereco;
        this.porta = porta;
        this.hostDiretorio = hostDiretorio;
        this.portaDiretorio = portaDiretorio;
        iniciar();
    }

    public void iniciar() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                ServerSocket serverSocket = null;
                try {
                    serverSocket = new ServerSocket(porta);
                    System.out.println("[" + nome + "] Rodando em " + endereco + " (porta real: " + porta + ")...");

                    // Registra-se no Servidor de Diretório
                    registrarNoDiretorio();

                    while (true) {
                        Socket cliente = serverSocket.accept();
                        atenderCliente(cliente);
                    }
                } catch (IOException e) {
                    System.err.println("[" + nome + "] Erro no servidor: " + e.getMessage());
                } finally {
                    if (serverSocket != null) {
                        try {
                            serverSocket.close();
                        } catch (IOException e) {
                            System.err.println("[" + nome + "] Erro ao fechar servidor: " + e.getMessage());
                        }
                    }
                }
            }
        }).start();
    }

    private void registrarNoDiretorio() {
        try (Socket socketDir = new Socket(hostDiretorio, portaDiretorio)) {
            OutputStream saida = socketDir.getOutputStream();
            InputStream entrada = socketDir.getInputStream();

            // Serviços oferecidos pela calculadora básica
            String servicos = "SOMA,SUBTRACAO,MULTIPLICACAO,DIVISAO";
            String msgRegistro = "REGISTER|" + nome + "|" + endereco + "|" + porta + "|" + servicos;

            saida.write(msgRegistro.getBytes("UTF-8"));

            byte[] buffer = new byte[512];
            int bytesLidos = entrada.read(buffer);
            if (bytesLidos > 0) {
                String resposta = new String(buffer, 0, bytesLidos, "UTF-8");
                System.out.println("[" + nome + "] Resposta do Diretório: " + resposta);
            }
        } catch (IOException e) {
            System.err.println("[" + nome + "] Não foi possível registrar no Diretório: " + e.getMessage());
        }
    }

    private void atenderCliente(Socket cliente) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    InputStream entrada = cliente.getInputStream();
                    OutputStream saida = cliente.getOutputStream();

                    byte[] buffer = new byte[512];
                    int bytesLidos = entrada.read(buffer);

                    if (bytesLidos > 0) {
                        String msg = new String(buffer, 0, bytesLidos, "UTF-8").trim();

                        if (msg.equals("PING")) {
                            saida.write("PONG".getBytes("UTF-8"));
                            return;
                        }

                        // Formato esperado: CALC|OPERACAO|num1|num2
                        if (msg.startsWith("CALC|")) {
                            String[] partes = msg.split("\\|");
                            if (partes.length == 4) {
                                String operacao = partes[1].trim().toUpperCase();
                                double a = Double.parseDouble(partes[2].trim());
                                double b = Double.parseDouble(partes[3].trim());

                                String resposta = processarCalculo(operacao, a, b);
                                saida.write(resposta.getBytes("UTF-8"));
                                System.out.println("[" + nome + " - " + endereco + "] Atendeu '" + operacao + "' -> " + resposta);
                            } else {
                                saida.write("ERRO|Formato inválido. Use: CALC|OPERACAO|num1|num2".getBytes("UTF-8"));
                            }
                        }
                    }
                } catch (Exception e) {
                    System.err.println("[" + nome + "] Erro ao atender cliente: " + e.getMessage());
                } finally {
                    try {
                        cliente.close();
                    } catch (IOException e) {
                        System.err.println("[" + nome + "] Erro ao fechar conexão com cliente: " + e.getMessage());
                    }
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
                return "ERRO|Operação desconhecida: " + operacao;
        }

        return "RESULTADO [" + nome + " (" + endereco + ")]: " + a + " " + simbolo + " " + b + " = " + resultado;
    }

    public static void main(String[] args) {
        new ServidorCalculadora("ServidorCalc1", "192.168.0.101", 7001, "localhost", ServidorDiretorio.PORTA_DIRETORIO);
        new ServidorCalculadora("ServidorCalc2", "192.168.0.102", 7002, "localhost", ServidorDiretorio.PORTA_DIRETORIO);
        new ServidorCalculadora("ServidorCalc3", "192.168.0.103", 7003, "localhost", ServidorDiretorio.PORTA_DIRETORIO);
    }
}
