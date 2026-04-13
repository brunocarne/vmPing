# Análise do Projeto vmPing

## 1. Visão Geral do Projeto
O `vmPing` (Visual Multi Ping) é um utilitário escrito em C# utilizando Windows Presentation Foundation (WPF) para interface gráfica. O seu foco é o monitoramento constante de múltiplos serviços e hosts usando abas interativas. O código está bem estruturado com a separação fluída entre a interface gráfica (`Views`) e as regras lógicas de rede (`Classes/Probes`).

## 2. Pontos Relevantes
* **Execução Limpa e Desacoplada**: A implementação de tarefas de varredura (ICMP Ping, TCP Port Ping, etc.) é manipulada eficientemente dentro de Threads via `Task` e de modo assíncrono.
* **Componente de DNS Eficiênte**: O serviço `DnsLookupService.cs` demonstra ser mais ágil e detalhado do que depender puramente das APIs limitadas nativas do Windows ou `.NET`. Ele faz o *parsing* manual dos pacotes UDP/DNS e exibe dados com rico detalhe técnico (como SOA, TXT e MX).

## 3. Brechas e Pontos Desnecessários
* **Processamento Duplicado no DNS Lookup (`DnsLookupService.cs`)**: Toda vez que uma chamada DNS é realizada, a aplicação simultaneamente envia e aguarda resposta dos adaptadores locais do computador (**Local DNS**) e sempre busca os 3 provedores públicos chumbados no código (Cloudflare `1.1.1.1`, Google `8.8.8.8` e Quad9 `9.9.9.9`). Isso não apenas cria tráfego UDP desnecessário como estende o tempo de latência se algum desses falhar no tempo de timeout. 
* **Traceroute ICMP Restrito**: A atual probe de Traceroute usa apenas ICMP (PingReply) com incremento do TTL do pacote. Redes corporativas frequentemente dropam ICMP, resultando em falsos positivos na rota ou nós marcados errôneamente como indisponíveis (aparecendo "* *" na rota).

## 4. Validação das Funções Requeridas

### A. Função DIG
* **Status Atual**: **Implementada com sucesso, porém indiretamente**.
* **Validação**: Toda a funcionalidade contida no `DnsLookupService.cs` funciona de modo exatamente análogo ao comando `dig` no Linux (com envio raw do query DNS e tradução do pacote em registros `A`, `CNAME`, `MX`, etc). A funcionalidade é muito completa na inspeção do pacote bruto.

### B. DNS Traceroute (DIG +trace)
* **Status Atual**: **Não existe no projeto**.
* **Validação**: Atualmente o menu Traceroute realiza o Trace ICMP até o servidor/IP, o que demonstra os "pulos - hops" da rede (roteadores). Porém, não há funcionalidade para **Trace de Delegação DNS** (o famoso `dig +trace`), que perante um domínio testa em sequência desde o Servidor Root (.), os Servidores TLD (ex: `.com`) até os Name Servers Autoritativos. Esta adição seria uma das funções mais pedidas por engenheiros de redes ou desenvolvedores web que usarem a ferramenta.

### C. Validação do DNS Local e DNS Externo quando solicitado via Menu
* **Status Atual**: **Falho/Indisponível na Interface Gráfica**.
* **Validação**: Como mencionado nas "Brechas", a tela atual `DnsLookupWindow.xaml` (ao apertar Ctrl-D) contém apenas um campo textual e o botão de *"Lookup"*. **Não há** um menu, dropdown, ou filtro para o tipo de validação de DNS! O Backend mescla tudo. O usuário não consegue separar testes feitos exclusivamente pelos DNS locais da empresa contra testes puros em roteadores públicos, impossibilitando diagnosticar se um problema de hostname é no DHCP local ou numa entrada mal propagada do Cloudflare.

## 5. Melhorias e Novas Funções (Recomendações)
1. **Adicionar Menu/Seletor de Escopo DNS**: Modificar o `DnsLookupWindow` inserindo um "Filter" (Dropdown) contendo opções claras: "Todos os Servidores", "Apenas Servidores Locais" e "Apenas Servidores Públicos".
2. **Nova Função: "DNS Trace" (Delegação)**: Modificar a ferramenta permitindo um fluxo que valide a trilha de propagação do nome até a raiz.
3. **Múltiplos Tipos de Traceroute**: Permitir parametrizar o Traceroute na interface para Traceroute por ICMP, UDP ou TCP (em portas específicas).
