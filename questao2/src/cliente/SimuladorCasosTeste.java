package cliente;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import javax.crypto.SecretKey;

import diretorio.ServidorDiretorio;
import log.Color;
import seguranca.CriptoUtils;
import seguranca.EnvelopeCriptografico;
import servidor.ServidorCalculadora;

/**
 * Arquivo isolado para execução automatizada dos Casos de Teste 1, 2 e 3
 * da camada de segurança híbrida (AES + HMAC + Assinatura Digital RSA).
 */
public class SimuladorCasosTeste {

    public static void main(String[] args) throws Exception {
        Color.info("====================================================================================");
        Color.info("  SIMULAÇÃO DOS CASOS DE TESTE - CAMADA DE SEGURANÇA HÍBRIDA (AES + HMAC + RSA)");
        Color.info("====================================================================================\n");

        // =========================================================================
        // CASO 1: Descoberta de serviço e cifra híbrida no diretório
        // =========================================================================
        Color.info("------------------------------------------------------------------------------------");
        Color.info("CASO 1: Descoberta de serviço e cifra híbrida no Diretório");
        Color.info("Participantes: Cliente 1, Servidor de Diretório e Servidores de Calc (S1, S2, S3)");
        Color.info("------------------------------------------------------------------------------------");

        ServidorDiretorio diretorio = new ServidorDiretorio(true);
        Thread.sleep(300);

        // S1, S2 e S3 registram seus serviços no Diretório usando pacotes cifrados (RSA+AES+HMAC)
        ServidorCalculadora s1 = new ServidorCalculadora("S1", "192.168.0.101", 7001, "localhost", ServidorDiretorio.PORTA_DIRETORIO);
        Thread.sleep(200);
        ServidorCalculadora s2 = new ServidorCalculadora("S2", "192.168.0.102", 7002, "localhost", ServidorDiretorio.PORTA_DIRETORIO);
        Thread.sleep(200);
        ServidorCalculadora s3 = new ServidorCalculadora("S3", "192.168.0.103", 7003, "localhost", ServidorDiretorio.PORTA_DIRETORIO);
        Thread.sleep(400);

        // Cliente 1 estabelece canal seguro com o Diretório e solicita o serviço "Calcular soma"
        Cliente cliente1 = new Cliente("Cliente 1", "localhost", ServidorDiretorio.PORTA_DIRETORIO, false);
        Color.info("[Caso 1] Cliente 1 solicitando o serviço 'Calcular soma' ao Diretório...");
        String respostaCaso1 = cliente1.descobrirServicoNoDiretorio("Calcular soma");
        Color.sucesso("[Caso 1 - Resultado] Pacote autenticado recebido por Cliente 1: " + respostaCaso1);
        Color.sucesso("[Caso 1 - Resultado] Logs do canal seguro gravados em tempo real em 'logs_canal_seguro.txt'.\n");

        // =========================================================================
        // CASO 2: Chamada de serviço com Load Balancing (Round-Robin)
        // =========================================================================
        Color.info("------------------------------------------------------------------------------------");
        Color.info("CASO 2: Chamada de serviço com Load Balancing (Round-Robin)");
        Color.info("Participantes: Cliente 1, Cliente 2 e Servidores de Calc (S1, S2)");
        Color.info("------------------------------------------------------------------------------------");

        // Para o Caso 2 (apenas S1 e S2 no balanceamento), marcamos S3 temporariamente como INATIVO no Diretório
        alterarStatusServidorNoDiretorio("S3", "INATIVO");
        diretorio.resetarIndiceRodizio();
        Thread.sleep(200);

        Cliente cliente2 = new Cliente("Cliente 2", "localhost", ServidorDiretorio.PORTA_DIRETORIO, false);

        // 1ª Chamada: Cliente 1 requisita 10 + 20 -> Round-Robin seleciona S1
        Color.info("[Caso 2 - 1ª Chamada] Cliente 1 requisitando cálculo: 10 + 20 (Calcular soma)...");
        cliente1.descobrirECalcular("Calcular soma", 10, 20, false);
        Thread.sleep(200);

        // 2ª Chamada: Cliente 2 requisita 5 * 4 -> Round-Robin alterna para S2
        Color.info("[Caso 2 - 2ª Chamada] Cliente 2 requisitando cálculo: 5 * 4 (Calcular multiplicacao)...");
        cliente2.descobrirECalcular("Calcular multiplicacao", 5, 4, false);
        Thread.sleep(200);

        // =========================================================================
        // CASO 3: Servidor inativo ou falha de integridade
        // =========================================================================
        Color.info("------------------------------------------------------------------------------------");
        Color.info("CASO 3: Servidor inativo ou falha de integridade");
        Color.info("Participantes: Cliente 3, Diretório e Servidor de Calc (S3 indisponível/adulterado)");
        Color.info("------------------------------------------------------------------------------------");

        Cliente cliente3 = new Cliente("Cliente 3", "localhost", ServidorDiretorio.PORTA_DIRETORIO, false);

        // Subcaso 3.1: Entrada inválida na consulta (operação "Calcular modulo" não cadastrada)
        Color.info("[Caso 3A - Entrada Inválida] Cliente 3 consultando serviço não cadastrado ('Calcular modulo'):");
        cliente3.descobrirServicoNoDiretorio("Calcular modulo");
        Thread.sleep(200);

        // Subcaso 3.2: S3 adulterado -> HMAC falha na negociação/resposta com S3
        Color.info("[Caso 3B - Falha de Integridade (HMAC Corrompido em S3)]:");
        s3.setSimularHmacCorrompido(true);
        cliente3.executarChamadaServidorCalculo("S3", "192.168.0.103", 7003, "Calcular soma", "15", "25", false);
        Thread.sleep(200);

        // Subcaso 3.3: Cliente 3 envia pacote com HMAC corrompido na negociação com S3
        Color.info("[Caso 3C - Falha de Integridade (Pacote do Cliente com HMAC Corrompido)]:");
        s3.setSimularHmacCorrompido(false);
        cliente3.executarChamadaServidorCalculo("S3", "192.168.0.103", 7003, "Calcular soma", "15", "25", true);
        Thread.sleep(200);

        // Subcaso 3.4: S3 inativo/indisponível -> Falha de conexão tratada sem travar
        Color.info("[Caso 3D - Servidor S3 Indisponível/Inativo]:");
        s3.pararServidor();
        Thread.sleep(200);
        cliente3.executarChamadaServidorCalculo("S3", "192.168.0.103", 7003, "Calcular soma", "15", "25", false);

        // Comprova que os demais componentes (Diretório, S1, S2) continuam funcionando normalmente sem travar
        Color.info("[Caso 3 - Verificação de Resiliência] Confirmando que Diretório e S1/S2 seguem operantes:");
        cliente1.descobrirECalcular("Calcular soma", 100, 50, false);

        // Encerra servidores do teste
        s1.pararServidor();
        s2.pararServidor();
        diretorio.fechar();

        Color.sucesso("====================================================================================");
        Color.sucesso("  TODOS OS CASOS DE TESTE (1, 2 e 3) FORAM EXECUTADOS COM SUCESSO!");
        Color.sucesso("====================================================================================");
        System.exit(0);
    }

    private static void alterarStatusServidorNoDiretorio(String nomeServidor, String novoStatus) {
        try (
                Socket socket = new Socket("localhost", ServidorDiretorio.PORTA_DIRETORIO);
                PrintWriter escritor = new PrintWriter(
                        new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);
                BufferedReader leitor = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))
        ) {
            KeyPair rsaAdmin = CriptoUtils.gerarParChavesRSA();
            SecretKey aesAdmin = CriptoUtils.gerarChaveAES();
            SecretKey hmacAdmin = CriptoUtils.gerarChaveHMAC();

            String envStatus = EnvelopeCriptografico.criarEnvelope(
                    "STATUS|" + nomeServidor + "|" + novoStatus,
                    aesAdmin,
                    hmacAdmin,
                    rsaAdmin,
                    "AdminTeste"
            );
            escritor.println(envStatus);
            leitor.readLine();

            String envQuit = EnvelopeCriptografico.criarEnvelope(
                    "QUIT",
                    aesAdmin,
                    hmacAdmin,
                    rsaAdmin,
                    "AdminTeste"
            );
            escritor.println(envQuit);
        } catch (Exception e) {
            Color.erro("Erro ao alterar status de " + nomeServidor + ": " + e.getMessage());
        }
    }
}
