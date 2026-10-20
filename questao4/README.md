4. CDN: Uma Content Delivery Network (CDN) é uma infraestrutura distribuída composta por servidores
estrategicamente posicionados (Edge Servers ou Points of Presence - PoPs) interligados pela internet. O
objetivo fundamental é aproximar o conteúdo do usuário final, reduzindo a latência, otimizando o
consumo de banda e aumentando a resiliência do serviço.
● Aplicações reais de CDNs:
○ Streaming: Entrega mídia em blocos (.ts/.m4s) para reduzir latência e evitar
buffering (ex.: Netflix, Spotify).
○ Downloads grandes: Suporta picos de tráfego em jogos e atualizações de SO
(ex.: Steam, PSN).
○ Aceleração Web: Salva recursos estáticos (CSS, JS, imagens) na borda para
carregamento rápido (ex.: e-commerce).
○ Proteção DDoS: Absorve ataques volumétricos na borda, protegendo o servidor
de origem.
4.1. Simulação: Arquitetura da CDN baseada em Sockets.
● Para simular o funcionamento interno de uma CDN com sockets, o sistema deve ser dividido em
quatro componentes principais:
Figura 1: Arquitetura simplificada de uma CDN.
○ Origin Server (Servidor de Origem).
■ Socket: TCP escutando em uma porta fixa (ex: 8000).
■ Papel: Armazena o banco de dados/arquivos mestre.
■ Lógica: Recebe uma requisição socket, busca o arquivo local no disco e responde
o conteúdo bruto.
■ O servidor armazena 1000 arquivos (pode usar a mesma nomenclatura da
questão 3).
○ Edge Servers/ Cache Nodes(Nós de Borda).
■ Socket:
● Servidor TCP: Escuta requisições dos clientes (ex: portas 8001, 8002,
8003).
● Cliente TCP: Abre uma conexão com o servidor de origem em caso de
cache miss.
■ Lógica:
● Mantém uma tabela hash/dicionário em memória (cache).
● Ao receber a mensagem do cliente:
○ Cache hit: Retorna o dado imediatamente.
○ Cache miss: Abre socket com a Origem, baixa o dado, salva na
memória/disco local e envia de volta ao cliente.
○ Router / GeoDNS (Direcionador de Tráfego).
■ Socket: UDP ou TCP escutando numa porta principal (ex: 5353).
■ Lógica:
● Recebe a solicitação do Cliente:"Onde baixo o arquivo X?".
● Avalia a localização fictícia do Cliente (enviada no payload).
● Responde ao cliente com o IP/Porta do Edge Server.
○ Cliente (Gerador de Tráfego).
■ Socket: Cliente TCP/UDP.
■ Lógica:
● Consulta o Router para descobrir a qual Edge se conectar.
● Estabelece conexão socket TCP com o Edge fornecido.
● Protocolo de aplicação simplificado.
○ Em vez de usar HTTP completo, você pode definir um protocolo simples baseado em
texto/JSON transmitido sobre os sockets TCP:
■ Requisição do Cliente para o Edge:
● GET /arquivo12.ext
● Resposta do Edge (cache hit):
○ 200 OK
○ Cache: HIT
○ Length: 1024
● Notificação de Invalidação (Origin -> Edges):
○ INVALIDATE /arquivo12.ext
● Casos de teste.
○ Para validar o funcionamento da CDN, aplique cenários de teste que demonstrem
algumas propriedades de sistemas distribuídos:
■ Caso 1: Validação de cache HIT vs. cache MISS em canal cifrado.
● Cliente, Router/GeoDNS, Edge e Servidor de Origem.
● Fluxo:
○ Cliente consulta Router (via UDP cifrado) e recebe IP/Porta do
Edge.
○ Primeira requisição (GET /arquivo20.ext): Edge verifica Cache
MISS. Abre socket TCP cifrado com a Origem, baixa o arquivo
via AES+HMAC, salva em cache e envia cifrado ao Cliente.
○ Segunda requisição (GET /arquivo20.ext): Edge identifica Cache
HIT. Responde imediatamente ao cliente com o dado do cache
local cifrado.
○ Resultado:
■ A segunda resposta apresenta tempo menor na
prática;
■ logs registram HIT e MISS com HMAC validado nas
duas pontas.
■ Caso 2: Expiração por TTL e invalidação ativa (INVALIDATE).
● Servidor de Origem, Edge e Cliente.
● Fluxo: Arquivo em cache expira após TTL (ex.: 10s) ou a Origem envia
comando INVALIDATE /arquivo30.ext cifrado via TCP para os Edges.
● Edge recebe, decripta a invalidação com a chave da Origem, checa
HMAC e remove arquivo30.ext do cache.
● Próxima requisição do Cliente força um Cache MISS, obrigando nova
busca segura na Origem.
● Resultado: Consistência estrita garantida e logs confirmam a
invalidação e renovação segura do cache.
■ Caso 3: Requisição inexistente / Erro na cifra da borda.
● Cliente e Edge.
● Fluxo: Cliente envia pedido de arquivo com nome fora do
padrão/inválido (GET /arquivoXYZ.ext) ou ocorre erro de decifragem
no handshake.
● Resultado:
○ Formato/arquivo inválido: Sistema não consulta a Origem e
retorna/imprime Erro na entrada de dados. Tente outra vez!.
○ Envio de mensagem sem o HMAC correto (ou usando um hash
sem chave): O Edge encerra a conexão de socket com o cliente,
emitindo alerta no log sem corromper a tabela de cache.