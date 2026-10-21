package log;

public class Color {

    public static final String RESET = "\u001B[0m";
    public static final String NEGRITO = "\u001B[1m";

    public static final String VERMELHO = "\u001B[31m";
    public static final String VERDE = "\u001B[32m";
    public static final String AMARELO = "\u001B[33m";
    public static final String AZUL = "\u001B[34m";
    public static final String ROXO = "\u001B[35m";
    public static final String CIANO = "\u001B[36m";

    public static final String VERMELHO_BRILHANTE = "\u001B[91m";
    public static final String VERDE_BRILHANTE = "\u001B[92m";
    public static final String AMARELO_BRILHANTE = "\u001B[93m";
    public static final String AZUL_BRILHANTE = "\u001B[94m";
    public static final String CIANO_BRILHANTE = "\u001B[96m";

    public static void erro(String mensagem) {
        System.out.println(VERMELHO_BRILHANTE + NEGRITO + "[ERRO] " + RESET + VERMELHO + mensagem + RESET);
        System.out.flush();
    }

    public static void info(String mensagem) {
        System.out.println(CIANO_BRILHANTE + NEGRITO + "[INFO] " + RESET + CIANO + mensagem + RESET);
        System.out.flush();
    }

    public static void sucesso(String mensagem) {
        System.out.println(VERDE_BRILHANTE + NEGRITO + "[SUCESSO] " + RESET + VERDE + mensagem + RESET);
        System.out.flush();
    }

    public static void alerta(String mensagem) {
        System.out.println(AMARELO_BRILHANTE + NEGRITO + "[ALERTA] " + RESET + AMARELO + mensagem + RESET);
        System.out.flush();
    }

    public static void enviado(String mensagem) {
        System.out.println("  " + AZUL_BRILHANTE + NEGRITO + "[LOG-ENVIADO] " + RESET + AZUL + mensagem + RESET);
        System.out.flush();
    }

    public static void recebido(String mensagem) {
        System.out.println("  " + ROXO + NEGRITO + "[LOG-RECEBIDO] " + RESET + ROXO + mensagem + RESET);
        System.out.flush();
    }

    public static void seguranca(String mensagem) {
        System.out.println("  " + VERDE_BRILHANTE + NEGRITO + "[SEGURANCA-CRIPTO] " + RESET + VERDE + mensagem + RESET);
        System.out.flush();
    }

    public static String formatarErro(String mensagem) {
        return VERMELHO_BRILHANTE + mensagem + RESET;
    }

    public static String formatarInfo(String mensagem) {
        return CIANO_BRILHANTE + mensagem + RESET;
    }

    public static String formatarSucesso(String mensagem) {
        return VERDE_BRILHANTE + mensagem + RESET;
    }

    public static String formatarAlerta(String mensagem) {
        return AMARELO_BRILHANTE + mensagem + RESET;
    }
}
