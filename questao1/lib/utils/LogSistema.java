package utils;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class LogSistema {
    private static final DateTimeFormatter DATA = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    private static final int LIMITE_AMOSTRA = 64;
    private final Path arquivo;

    public LogSistema(Path arquivo) {
        this.arquivo = arquivo.toAbsolutePath().normalize();
    }

    // Encontra raiz a partir da pasta atual ou de seus ancestrais.
    public static LogSistema noProjeto(String nomeProjeto) {

        Path atual = Paths.get("").toAbsolutePath().normalize();
        for (Path pasta = atual; pasta != null; pasta = pasta.getParent()) {
            if (pasta.getFileName() != null && pasta.getFileName().toString().equals(nomeProjeto)) {
                return new LogSistema(pasta.resolve("logs_canal_seguro.txt"));
            }
            Path filho = pasta.resolve(nomeProjeto);
            if (Files.isDirectory(filho)) {
                return new LogSistema(filho.resolve("logs_canal_seguro.txt"));
            }
        }
        return new LogSistema(atual.resolve("logs_canal_seguro.txt"));
    }

    // Registrar só amostras de envelopes cifrados ou dados operacionais; nunca chaves privadas/AES/HMAC
    // Sincroniza threads locais e usa FileLock para coordenar processos distintos
    public void registrar(String emissor, String destinatario, String evento, String conteudo) {
        String amostra = conteudo == null ? "-" : conteudo.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');
        if (amostra.length() > LIMITE_AMOSTRA) {
            amostra = amostra.substring(0, LIMITE_AMOSTRA) + "...";
        }

        synchronized (LogSistema.class) {
            try {
                Path pasta = arquivo.getParent();
                if (pasta != null) {
                    Files.createDirectories(pasta);
                }
                try (FileChannel canal = FileChannel.open(arquivo, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                        FileLock trava = canal.lock()) {
                    String linha = "[" + LocalDateTime.now().format(DATA) + "] [" + emissor + " -> " + destinatario
                            + "] [" + evento + "] " + amostra + System.lineSeparator();
                    ByteBuffer bytes = StandardCharsets.UTF_8.encode(linha);
                    canal.position(canal.size());
                    while (bytes.hasRemaining()) {
                        canal.write(bytes);
                    }
                }
            } catch (IOException e) {
                System.err.println("Falha ao gravar log em " + arquivo + ": " + e.getMessage());
            }
        }
    }
}
