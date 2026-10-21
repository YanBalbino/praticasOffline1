import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import utils.ImplAES256;
import utils.ImplHMAC;
import utils.ImplRSA;
import utils.LogSistema;
import utils.SessaoCliente;

public class ServidorDNS {
    private static final LogSistema LOG = LogSistema.noProjeto("questao1");
    private final int PORTA_DNS = 5959;
    private final HashMap<String, String> tabelaDNS = new HashMap<>();

    // IP + porta UDP identificam por onde responder e qual chave usar para cada cliente
    private final Map<InetSocketAddress, SessaoCliente> sessoes = new HashMap<>();
    private DatagramSocket socket;

    private ImplRSA rsa;
    private final ImplAES256 aes = new ImplAES256();

    public ServidorDNS() {
        for (int i = 1; i <= 10; i++) {
            String nome = "servidor" + i;
            String enderecoIP = "192.168.0." + (i * 10);
            tabelaDNS.put(nome, enderecoIP);
        }
        rodar();
    }

    private void rodar() {
        try {
            // Um par RSA para o servidor inteiro, não um novo par para cada cliente.
            rsa = new ImplRSA();
            socket = new DatagramSocket(PORTA_DNS);
            InetAddress host = InetAddress.getLocalHost();
            System.out.println("Servidor DNS rodando em: " + host.getHostAddress() + ":" + PORTA_DNS + "...");

            while (true) {
                byte[] buffer = new byte[4096];
                DatagramPacket pacoteRecebido = new DatagramPacket(buffer, buffer.length);
                try {
                    socket.receive(pacoteRecebido);
                    InetSocketAddress origem = new InetSocketAddress(pacoteRecebido.getAddress(), pacoteRecebido.getPort());
                    String mensagemRecebida = new String(buffer, 0, pacoteRecebido.getLength(), StandardCharsets.UTF_8);
                    String cliente = "Cliente:" + origem.getPort();
                    LOG.registrar(cliente, "DNS", "UDP RECEBIDO", mensagemRecebida);

                    if (mensagemRecebida.startsWith("HELLO|")) {
                        tratarHello(mensagemRecebida, origem);
                    } else if (mensagemRecebida.startsWith("SESSION|")) {
                        tratarSessao(mensagemRecebida, origem);
                    } else {
                        SessaoCliente sessao = sessoes.get(origem);
                        if (sessao == null || !sessao.isPronta()) {
                            System.err.println("Cliente sem sessão pronta: " + origem);
                            LOG.registrar(cliente, "DNS", "PACOTE DESCARTADO", mensagemRecebida);
                            continue;
                        }

                        // Verificar assinatura do HMAC antes de qualquer comando.
                        String comando = verificarEDecifrar(mensagemRecebida, sessao);
                        if (comando == null) {
                            LOG.registrar(cliente, "DNS", "HMAC INVALIDO", mensagemRecebida);
                            System.err.println("[ERROR] Assinatura/HMAC inválido de " + origem + ". Mensagem ignorada.");
                            continue;
                        }
                        System.out.println("Mensagem de " + origem + ": " + comando);
                        LOG.registrar(cliente, "DNS", "HMAC OK " + comando.split("\\|", 2)[0], comando);
                        processarComando(comando, origem, sessao);
                    }
                } catch (IOException | GeneralSecurityException | RuntimeException e) {
                    // Datagrama inválido não deve derrubar o servidor nem outros clientes.
                    LOG.registrar("Cliente", "DNS", "FALHA PACOTE", e.getMessage());
                    System.err.println("Erro ao processar pacote: " + e.getMessage());
                    if (socket.isClosed()) break;
                }
            }
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Erro no servidor: " + e.getMessage());
        } finally {
            if (socket != null) socket.close();
        }
    }

    private void tratarHello(String mensagem, InetSocketAddress origem)
            throws IOException, GeneralSecurityException {
        String[] partes = mensagem.split("\\|", -1);
        if (partes.length != 2) throw new IllegalArgumentException("HELLO inválido.");

        // Troca de públicas sem assinatura/autenticação, conforme escopo do trabalho.
        byte[] dadosPublicos = Base64.getDecoder().decode(partes[1]);
        PublicKey publicaCliente = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(dadosPublicos));
        sessoes.put(origem, new SessaoCliente(publicaCliente));
        System.out.println("HELLO de " + origem + ": chave pública recebida.");

        String resposta = "PUBLIC_KEY|" + Base64.getEncoder().encodeToString(rsa.getChavePublica().getEncoded());
        byte[] dados = resposta.getBytes(StandardCharsets.UTF_8);
        socket.send(new DatagramPacket(dados, dados.length, origem.getAddress(), origem.getPort()));
        LOG.registrar("DNS", "Cliente:" + origem.getPort(), "UDP ENVIO PUBLIC_KEY", resposta);
        System.out.println("Chave pública do servidor enviada a " + origem + ".");
    }

    private void tratarSessao(String mensagem, InetSocketAddress origem)
            throws IOException, GeneralSecurityException {
        SessaoCliente sessao = sessoes.get(origem);
        if (sessao == null) throw new IllegalArgumentException("SESSION sem HELLO de " + origem);

        String[] partes = mensagem.split("\\|", -1);
        if (partes.length != 3) throw new IllegalArgumentException("SESSION inválida.");
        // Cliente envia as duas chaves separadas; somente privada RSA do servidor as recupera.
        byte[] bytesAES = rsa.decifrar(Base64.getDecoder().decode(partes[1]));
        byte[] bytesHMAC = rsa.decifrar(Base64.getDecoder().decode(partes[2]));
        if (bytesAES.length != 32 || bytesHMAC.length != 32) {
            throw new IllegalArgumentException("Tamanho de chave de sessão inválido.");
        }
        SecretKey chaveAES = new SecretKeySpec(bytesAES, "AES");

        // Assinamos o HMAC do SESSION com a privada RSA do servidor.
        // Cliente recalcula o HMAC e verifica com a pública recebida no HELLO.
        byte[] macConfirmacao = ImplHMAC.gerarMAC(mensagem.getBytes(StandardCharsets.UTF_8), bytesHMAC);
        byte[] assinatura = rsa.assinar(macConfirmacao);
        String confirmacao = "SESSION_OK|" + Base64.getEncoder().encodeToString(assinatura);
        byte[] dados = confirmacao.getBytes(StandardCharsets.UTF_8);
        socket.send(new DatagramPacket(dados, dados.length, origem.getAddress(), origem.getPort()));
        LOG.registrar("DNS", "Cliente:" + origem.getPort(), "UDP ENVIO SESSION_OK", confirmacao);
        sessao.confirmar(chaveAES, bytesHMAC);
        LOG.registrar("Cliente:" + origem.getPort(), "DNS", "SESSAO PRONTA", "Handshake AES/HMAC confirmado");
        System.out.println("Sessão AES/HMAC confirmada com " + origem + ".");
    }

    private String verificarEDecifrar(String envelope, SessaoCliente sessao)
            throws GeneralSecurityException {
        String[] partes = envelope.split("\\|", -1);
        if (partes.length != 3 || !"DATA".equals(partes[0])) {
            throw new IllegalArgumentException("Formato de envelope inválido.");
        }
        String conteudo = partes[0] + "|" + partes[1];
        byte[] macEsperado = ImplHMAC.gerarMAC(conteudo.getBytes(StandardCharsets.UTF_8), sessao.getChaveHMAC());
        byte[] assinaturaRecebida = Base64.getDecoder().decode(partes[2]);
        try {
            // A pública guardada nesta sessão é a do cliente que enviou o pacote.
            if (!rsa.verificarAssinatura(macEsperado, assinaturaRecebida, sessao.getChavePublica())) return null;
        } catch (java.security.SignatureException e) {
            return null; // assinatura malformada: não processar comando nem encerrar servidor
        }
        byte[] cifrado = Base64.getDecoder().decode(partes[1]);
        return new String(aes.decifrar(cifrado, sessao.getChaveAES()), StandardCharsets.UTF_8);
    }

    private String cifrarEAutenticar(String mensagem, SessaoCliente sessao)
            throws GeneralSecurityException {
        byte[] cifrado = aes.cifrar(mensagem, sessao.getChaveAES());
        String conteudo = "DATA|" + Base64.getEncoder().encodeToString(cifrado);
        byte[] mac = ImplHMAC.gerarMAC(conteudo.getBytes(StandardCharsets.UTF_8), sessao.getChaveHMAC());
        // Uma assinatura do servidor para resposta ou notificação; HMAC não viaja separadamente.
        byte[] assinatura = rsa.assinar(mac);
        return conteudo + "|" + Base64.getEncoder().encodeToString(assinatura);
    }

    private void processarComando(String comando, InetSocketAddress origem, SessaoCliente sessao)
            throws IOException, GeneralSecurityException {
        String resposta;
        String nomeAlterado = null;
        String ipAntigo = null;
        String novoIP = null;

        if ("LIST".equals(comando)) {
            StringBuilder lista = new StringBuilder("Servidores:\n");
            for (Map.Entry<String, String> entry : tabelaDNS.entrySet()) {
                lista.append(entry.getKey()).append(" -> ").append(entry.getValue()).append('\n');
            }
            resposta = lista.append('\n').toString();
        } else if (comando.startsWith("GET|")) {
            String nomeServidor = comando.substring(4).trim();
            String enderecoIP = tabelaDNS.get(nomeServidor);
            resposta = enderecoIP == null
                    ? nomeServidor + " não encontrado. Tente outra vez!"
                    : "Endereço IP de " + nomeServidor + ": " + enderecoIP;
        } else if (comando.startsWith("SET|")) {
            String[] partes = comando.split("\\|", -1);
            if (partes.length != 3) {
                resposta = "[ERROR] Erro na entrada de dados. Tente outra vez! Use: SET|nomeServidor|novoEnderecoIP";
            } else {
                String nomeServidor = partes[1].trim();
                String enderecoIP = partes[2].trim();
                String antigo = tabelaDNS.get(nomeServidor);
                if (antigo == null) {
                    resposta = "Servidor " + nomeServidor + " não encontrado.";
                } else {
                    // Ainda falta autenticar identidade de registrador: isRegistrador só controla menu do cliente.
                    tabelaDNS.put(nomeServidor, enderecoIP);
                    resposta = "Endereço IP de " + nomeServidor + " atualizado para: " + enderecoIP + "\n";
                    nomeAlterado = nomeServidor;
                    ipAntigo = antigo;
                    novoIP = enderecoIP;
                }
            }
        } else if ("QUIT".equals(comando)) {
            sessoes.remove(origem);
            LOG.registrar("Cliente:" + origem.getPort(), "DNS", "QUIT", "Sessão encerrada");
            System.out.println("O cliente " + origem + " desconectou.");
            return; // cliente já fechou seu socket; não espera resposta de despedida
        } else {
            resposta = "Operação inválida.";
        }

        // Enviar resposta ANTES das notificações do SET.
        String mensagemSegura = cifrarEAutenticar(resposta, sessao);
        byte[] dados = mensagemSegura.getBytes(StandardCharsets.UTF_8);
        socket.send(new DatagramPacket(dados, dados.length, origem.getAddress(), origem.getPort()));
        LOG.registrar("DNS", "Cliente:" + origem.getPort(), "UDP ENVIO RESPOSTA", mensagemSegura);
        System.out.println("Resposta enviada a " + origem + ".");

        if (nomeAlterado != null) {
            System.out.println("IP de " + nomeAlterado + " alterado: " + ipAntigo + " -> " + novoIP);
            LOG.registrar("DNS", "Tabela DNS", "SET", nomeAlterado + " " + ipAntigo + " -> " + novoIP);
            notificarClientes(nomeAlterado, ipAntigo, novoIP);
        }
    }

    private void notificarClientes(String nomeServidor, String ipAntigo, String novoEnderecoIP) {
        String notificacao = "NOTIFY|ALTERACAO DE IP|" + nomeServidor + "|" + ipAntigo + "->" + novoEnderecoIP;
        int enviados = 0;
        // Cada cliente recebe notificação cifrada e autenticada com suas próprias chaves.
        for (Map.Entry<InetSocketAddress, SessaoCliente> entry : sessoes.entrySet()) {
            SessaoCliente sessao = entry.getValue();
            if (!sessao.isPronta()) continue;
            
            InetSocketAddress destino = entry.getKey();
            try {
                String mensagemSegura = cifrarEAutenticar(notificacao, sessao);
                byte[] dados = mensagemSegura.getBytes(StandardCharsets.UTF_8);
                socket.send(new DatagramPacket(dados, dados.length, destino.getAddress(), destino.getPort()));
                LOG.registrar("DNS", "Cliente:" + destino.getPort(), "UDP ENVIO NOTIFY", mensagemSegura);
                enviados++;
            } catch (IOException | GeneralSecurityException | RuntimeException e) {
                LOG.registrar("DNS", "Cliente:" + destino.getPort(), "FALHA NOTIFY", e.getMessage());
                System.err.println("Erro ao notificar " + destino + ": " + e.getMessage());
            }
        }
        System.out.println("Notificação enviada a " + enviados + " cliente(s).");
    }

    public static void main(String[] args) {
        new ServidorDNS();
    }
}
