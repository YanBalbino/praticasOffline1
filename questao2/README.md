# Questão 2 — Descoberta de Serviços com Criptografia Híbrida (RSA + AES + HMAC)

Este projeto implementa a arquitetura distribuída de **Descoberta de Serviços (Service Discovery)** com **Balanceamento de Carga (Round-Robin / Random)** e **Canal Seguro Híbrido (Handshake RSA + AES + HMAC + Assinatura Digital RSA)** entre **processos independentes**, atendendo integralmente aos requisitos descritos em [`docs/DescricaoProjeto.txt`](docs/DescricaoProjeto.txt).

---

## 1. Fluxo de Segurança Híbrida Implementado

A camada de segurança combina o protocolo de **Handshake RSA** (para estabelecimento confidencial de chaves de sessão simétricas por conexão) com o **Envelope Criptográfico Híbrido** (para confidencialidade, integridade, autenticidade e irretratabilidade em cada mensagem):

### 1.1. Fase 1: Handshake RSA e Estabelecimento de Sessão (`SessaoSegura`)
Sempre que um componente inicia uma conexão TCP (`ServidorCalculadora -> ServidorDiretorio`, `Cliente -> ServidorDiretorio` ou `Cliente -> ServidorCalculadora`):
1. **`HANDSHAKE_SERVER_HELLO`**: O servidor receptor envia sua identidade e sua **Chave Pública RSA** (2048 bits) codificada em Base64.
2. **Geração e Encapsulamento Assimétrico das Chaves de Sessão**: O iniciador (cliente) gera chaves simétricas efêmeras e exclusivas para a sessão (`AES-128` e `HmacSHA256`) e **cifra ambas com a Chave Pública RSA do Servidor** (`CriptoUtils.cifrarChaveSimetricaComPublicaRSA`).
3. **`HANDSHAKE_CLIENT_KEYS`**: O cliente envia as chaves `AES` e `HMAC` cifradas com RSA juntamente com sua própria **Chave Pública RSA**.
4. **Recuperação pelo Servidor**: O servidor decifra `chaveSessaoAES` e `chaveSessaoHMAC` utilizando exclusivamente sua **Chave Privada RSA** (`CriptoUtils.decifrarChaveAESComPrivadaRSA` e `decifrarChaveHMACComPrivadaRSA`).
5. **Sessão Bidirecional Compartilhada**: Tanto a requisição quanto a resposta trafegam na sessão utilizando as mesmas chaves simétricas acordadas (`chaveSessaoAES` e `chaveSessaoHMAC`).

### 1.2. Fase 2: Transporte de Mensagens via Envelope Criptográfico (`EnvelopeCriptografico`)
Em todas as mensagens de requisição e resposta (incluindo `REGISTER`, `DISCOVER`, `LIST`, `STATUS`, `PING`/`PONG`, `CALC` e `QUIT`):
1. **Confidencialidade da Mensagem (AES)**: O texto em claro é cifrado com `AES/ECB/PKCS5Padding` usando a `chaveSessaoAES`.
2. **Integridade (Encrypt-then-MAC com HMAC-SHA256)**: Calcula-se o hash `HmacSHA256` sobre o payload cifrado usando a `chaveSessaoHMAC`.
3. **Autenticidade e Irretratabilidade (Assinatura Digital RSA)**: O hash HMAC é cifrado com a **Chave Privada RSA do emissor** (`criptografarHmacComChavePrivadaRSA`).
4. **Proteção das Chaves Simétricas no Envelope (RSA Público do Destinatário)**: As chaves simétricas no envelope são encapsuladas com a **Chave Pública RSA do destinatário** (jamais trafegam em texto claro).
5. **Validação no Destinatário**:
   - Decifra as chaves simétricas com sua **Chave Privada RSA**;
   - Extrai o HMAC da assinatura digital usando a **Chave Pública RSA do emissor**;
   - Recalcula o HMAC localmente sobre o texto cifrado e compara em tempo constante (`MessageDigest.isEqual`);
   - Se o HMAC for válido, decifra a mensagem com `AES`; caso contrário, rejeita a execução imediatamente e registra o alerta em `logs_canal_seguro.txt`.

---

## 2. Resumo das Alterações Realizadas

1. **[`src/seguranca/CriptoUtils.java`](src/seguranca/CriptoUtils.java)**:
   - Adicionados os métodos `cifrarChaveSimetricaComPublicaRSA`, `decifrarChaveAESComPrivadaRSA` e `decifrarChaveHMACComPrivadaRSA` para encapsular as chaves de sessão `AES` e `HMAC` com criptografia assimétrica RSA (eliminando o envio de chaves simétricas em Base64 aberto).
2. **[`src/seguranca/SessaoSegura.java`](src/seguranca/SessaoSegura.java)** *(Novo)*:
   - Implementa o protocolo de Handshake RSA (`realizarHandshakeComoCliente` e `realizarHandshakeComoServidor`) e mantém o estado criptográfico compartilhado da sessão (`chaveSessaoAES`, `chaveSessaoHMAC`, `parChavesRSALocal`, `chavePublicaRSARemota`) para uso bidirecional (requisição e resposta).
3. **[`src/seguranca/EnvelopeCriptografico.java`](src/seguranca/EnvelopeCriptografico.java)**:
   - Atualizado para cifrar `chaveAES` e `chaveHMAC` com a `PublicKey` RSA do destinatário em `criarEnvelope` / `criarEnvelopeComHmacCorrompido` e decifrá-las com a `PrivateKey` RSA do destinatário em `abrirEValidarEnvelope`.
4. **[`src/diretorio/ServidorDiretorio.java`](src/diretorio/ServidorDiretorio.java)**:
   - Realiza Handshake RSA por conexão via `SessaoSegura` e responde usando as chaves de sessão negociadas com o cliente/servidor;
   - Criptografa integralmente o health-check `PING`/`PONG` (`verificarServidorOnlineSeguro`);
   - Suporta as políticas de balanceamento `ROUND_ROBIN` e `RANDOM`;
   - Registra o `PID` do processo do Sistema Operacional.
5. **[`src/servidor/ServidorCalculadora.java`](src/servidor/ServidorCalculadora.java)**:
   - Registra-se no Diretório e atende clientes estabelecendo `SessaoSegura` (Handshake RSA + chaves de sessão compartilhadas para requisição e resposta);
   - Responde a `PING` de forma cifrada (`PONG`);
   - Permite execução individual como processo independente via argumentos (`S1`, `S2`, `S3`) e registra o `PID` do processo.
6. **[`src/cliente/Cliente.java`](src/cliente/Cliente.java)**:
   - Utiliza `SessaoSegura` tanto na comunicação com o `ServidorDiretorio` quanto nas sessões individuais abertas com cada `ServidorCalculadora` selecionado pelo Load Balancer;
   - Suporta execução interativa (menu) e execução automatizada por linha de comando (`--discover` e `--calc`) como processo independente.
7. **Classes de Entrada para Processos Independentes (`src/impl/`)**:
   - [`ImplServidorDiretorio.java`](src/impl/ImplServidorDiretorio.java): Processo do Servidor de Diretório (porta `6000`).
   - [`ImplServidorS1.java`](src/impl/ImplServidorS1.java), [`ImplServidorS2.java`](src/impl/ImplServidorS2.java), [`ImplServidorS3.java`](src/impl/ImplServidorS3.java): Processos independentes dos Servidores de Calculadora `S1` (`7001`), `S2` (`7002`) e `S3` (`7003`).
   - [`ImplCliente1.java`](src/impl/ImplCliente1.java), [`ImplCliente2.java`](src/impl/ImplCliente2.java), [`ImplCliente3.java`](src/impl/ImplCliente3.java): Processos independentes dos 3 Clientes.
8. **[`src/cliente/SimuladorCasosTeste.java`](src/cliente/SimuladorCasosTeste.java)**:
   - Orquestra os Casos de Teste 1, 2 e 3 iniciando cada componente (`Diretório`, `S1`, `S2`, `S3`, `Cliente 1`, `Cliente 2`, `Cliente 3`) em **processos independentes do Sistema Operacional** via `ProcessBuilder`;
   - Garante que todos os subcasos do **Caso 3** (`3A` entrada inválida `"Calcular modulo"`, `3B` falha de HMAC vindo de `S3`, `3C` falha de HMAC enviado pelo `Cliente 3`, e `3D` servidor `S3` inativo/indisponível) realizem a consulta de descoberta no `ServidorDiretorio` antes da tentativa de conexão com `S3`.
