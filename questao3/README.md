# Questão 3 — Nomeação em P2P (Overlay em Anel Horário com Criptografia Híbrida Salto a Salto)

Este projeto implementa uma aplicação **Cliente/Servidor Multithread com UDP** e **Camada de Segurança com Criptografia Híbrida (`RSA + AES + HMAC-SHA256`)** para simular a comunicação e resolução distribuída de recursos (arquivos) entre **seis processos independentes (`P0`, `P1`, `P2`, `P3`, `P4` e `P5`)** organizados em uma **topologia em anel** com roteamento **exclusivamente no sentido horário**.

---

## 1. Arquitetura e Distribuição dos Recursos no Anel (Sentido Horário)

Cada nó percorre o anel no sentido horário (`P0 -> P1 -> P2 -> P3 -> P4 -> P5 -> P0`), estabelecendo um **canal seguro salto a salto** (troca de chaves de sessão `AES` e `HMAC` via `RSA`) a cada enlace:

| Processo | ID Numérico | Endereço Simulado | Porta UDP | Sucessor (Horário) | Arquivos Armazenados (Total: 60) |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **`P0`** | `0` | `192.168.0.100` | `8000` | `P1` | `arquivo1.ext` a `arquivo10.ext` |
| **`P1`** | `1` | `192.168.0.101` | `8001` | `P2` | `arquivo11.ext` a `arquivo20.ext` |
| **`P2`** | `2` | `192.168.0.102` | `8002` | `P3` | `arquivo21.ext` a `arquivo30.ext` |
| **`P3`** | `3` | `192.168.0.103` | `8003` | `P4` | `arquivo31.ext` a `arquivo40.ext` |
| **`P4`** | `4` | `192.168.0.104` | `8004` | `P5` | `arquivo41.ext` a `arquivo50.ext` |
| **`P5`** | `5` | `192.168.0.105` | `8005` | `P0` | `arquivo51.ext` a `arquivo60.ext` |

---

## 2. Casos de Teste Implementados

1. **Caso 1 — Busca válida com criptografia salto a salto**:
   - **Origem**: `P0` | **Arquivo**: `arquivo35.ext`
   - **Fluxo (Horário)**: `P0 -> P1 -> P2 -> P3`
   - **Resultado**: Cada enlace (`P0–P1`, `P1–P2`, `P2–P3`) estabelece canal seguro com troca de chaves `AES` via `RSA`. `P0` encripta com `AES/HMAC` e envia a `P1`; `P1` e `P2` decriptam, verificam integridade, não encontram localmente e re-encriptam para o próximo nó; `P3` decripta, localiza o arquivo (faixa `31–40`) e responde com mensagem cifrada a `P0`.
2. **Caso 2 — Entrada inválida**:
   - **Origem**: `P1` (`arquivo99.ext`) e `P4` (`arquivoABC.ext`).
   - **Resultado**: O nó valida o comando antes de iniciar criptografia ou abrir conexões de rede, rejeita a busca sem propagar pacotes pelo anel e imprime no console: `Erro na entrada de dados. Tente outra vez!`.
3. **Caso 3 — Falha de integridade / Pacote adulterado**:
   - **Origem**: `P4` enviando para `P5`.
   - **Cenário**: Mensagem cifrada alterada no canal ou `HMAC` inválido.
   - **Resultado**: `P5` detecta a divergência do `HMAC`, descarta o pacote, interrompe o repasse para `P0` e grava no log a falha de autenticação/integridade.

---

## 3. Como Compilar e Executar

### 3.1. Compilação
```bash
mkdir -p praticasOffline1/questao3/out/production/questao3
javac -d praticasOffline1/questao3/out/production/questao3 $(find praticasOffline1/questao3/src -name "*.java")
```

### 3.2. Executar a Simulação Completa Automatizada (Casos 1, 2 e 3)
```bash
java -cp praticasOffline1/questao3/out/production/questao3 cliente.SimuladorCasosTeste
```
