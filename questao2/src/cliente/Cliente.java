package cliente;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Scanner;

import diretorio.ServidorDiretorio;

public class Cliente {
    private String nomeCliente;
    private String hostDiretorio;
    private int portaDiretorio;

    public Cliente(String nomeCliente, String hostDiretorio, int portaDiretorio) {
        this.nomeCliente = nomeCliente;
        this.hostDiretorio = hostDiretorio;
        this.portaDiretorio = portaDiretorio;
        rodar();
    }

    private void rodar() {
        Socket socketDiretorio = null;

        try {
            socketDiretorio = new Socket(hostDiretorio, portaDiretorio);
            System.out.println("[" + nomeCliente + "] Conectado ao Servidor de Diretório!");

            OutputStream saidaDir = socketDiretorio.getOutputStream();
            InputStream entradaDir = socketDiretorio.getInputStream();

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
                        saidaDir.write("LIST".getBytes("UTF-8"));
                        String listagem = lerResposta(entradaDir);
                        System.out.println("\n" + listagem);
                        break;

                    case "1":
                        descobrirECalcular("SOMA", saidaDir, entradaDir, teclado);
                        break;

                    case "2":
                        descobrirECalcular("SUBTRACAO", saidaDir, entradaDir, teclado);
                        break;

                    case "3":
                        descobrirECalcular("MULTIPLICACAO", saidaDir, entradaDir, teclado);
                        break;

                    case "4":
                        descobrirECalcular("DIVISAO", saidaDir, entradaDir, teclado);
                        break;

                    case "5":
                        System.out.println("Qual o nome do servidor?");
                        String nomeSrv = teclado.nextLine().trim();
                        System.out.println("Qual o novo status? (ATIVO / INATIVO)");
                        String statusSrv = teclado.nextLine().trim().toUpperCase();
                        saidaDir.write(("STATUS|" + nomeSrv + "|" + statusSrv).getBytes("UTF-8"));
                        System.out.println("\nResposta do Diretório: " + lerResposta(entradaDir) + "\n");
                        break;

                    case "6":
                        saidaDir.write("QUIT".getBytes("UTF-8"));
                        System.out.println("[" + nomeCliente + "] Desconectando do Servidor de Diretório...");
                        socketDiretorio.close();
                        return;

                    default:
                        System.out.println("Operação inválida. Tente novamente.\n");
                        break;
                }
            }
        } catch (IOException e) {
            System.err.println("Erro ao se comunicar com o Servidor de Diretório: " + e.getMessage());
        } finally {
            if (socketDiretorio != null) {
                try {
                    socketDiretorio.close();
                } catch (IOException e) {
                    System.err.println("Erro ao fechar o socket: " + e.getMessage());
                }
            }
        }
    }

    private void descobrirECalcular(String operacao, OutputStream saidaDir, InputStream entradaDir, Scanner teclado)
            throws IOException {
        saidaDir.write(("DISCOVER|" + operacao).getBytes("UTF-8"));
        String respostaDir = lerResposta(entradaDir);

        if (respostaDir.startsWith("ERRO|")) {
            System.out.println("\n[Diretório]: " + respostaDir.substring(5) + "\n");
            return;
        }

        // OK|nomeServidor|ip|porta
        String[] partes = respostaDir.split("\\|");
        if (partes.length == 4 && partes[0].equals("OK")) {
            String nomeServidor = partes[1];
            String ip = partes[2];
            int portaServidor = Integer.parseInt(partes[3]);

            System.out.println("\n>>> [Descoberta de Serviço] Servidor ativo encontrado para '" + operacao + "': "
                    + nomeServidor + " (Endereço simulado: " + ip + ", Porta: " + portaServidor + ")");

            System.out.print("Digite o primeiro número: ");
            String num1 = teclado.nextLine().trim();
            System.out.print("Digite o segundo número: ");
            String num2 = teclado.nextLine().trim();

            try (Socket socketCalc = new Socket("localhost", portaServidor)) {
                OutputStream saidaCalc = socketCalc.getOutputStream();
                InputStream entradaCalc = socketCalc.getInputStream();

                String reqCalculo = "CALC|" + operacao + "|" + num1 + "|" + num2;
                saidaCalc.write(reqCalculo.getBytes("UTF-8"));

                String resultado = lerResposta(entradaCalc);
                System.out.println(">>> " + resultado + "\n");
            } catch (IOException e) {
                System.err.println("Erro ao conectar ao servidor de calculadora " + nomeServidor + ": " + e.getMessage());
            }
        } else {
            System.out.println("Resposta inesperada do Diretório: " + respostaDir);
        }
    }

    private String lerResposta(InputStream entrada) throws IOException {
        byte[] buffer = new byte[1024];
        int bytesLidos = entrada.read(buffer);
        if (bytesLidos > 0) {
            return new String(buffer, 0, bytesLidos, "UTF-8").trim();
        }
        return "";
    }

    private void menu() {
        System.out.println("=========================================================");
        System.out.println("OPERAÇÕES DE DESCOBERTA DE SERVIÇOS (" + nomeCliente + "):");
        System.out.println(
                "0 - Listar servidores registrados\n" +
                "1 - Soma\n" +
                "2 - Subtração\n" +
                "3 - Multiplicação\n" +
                "4 - Divisão\n" +
                "5 - STATUS\n" +
                "6 - Encerrar conexão"
        );
        System.out.print("Selecione uma operação: ");
    }

    public static void main(String[] args) {
        String nome = (args.length > 0) ? args[0] : "Cliente1";
        new Cliente(nome, "localhost", ServidorDiretorio.PORTA_DIRETORIO);
    }
}
