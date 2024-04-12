# OpenVAS Docker Compose

Este projeto configura e executa o OpenVAS usando Docker. Ele inclui todos os serviços necessários para executar o OpenVAS, bem como integra o resultado ao GAT Core.

## Pré-requisitos

- Docker
- Docker Compose
- Recomendado 8 Gb de memória

## Configuração

1. Clone este repositório:
   ```
   git clone https://github.com/danilofranco/integra-o-openvas-gatcore.git
   cd seu-repositorio
   ```

2. Defina as variáveis de ambiente necessárias no arquivo `.env` na raiz do projeto:
   ```
   OPENVAS_USERNAME=your_username
   OPENVAS_PASSWORD=your_password
   GAT_URL=https://your_gat_url
   GAT_TOKEN=your_gat_token
   ONPREMISE=False
   ```

3. Construa e inicie os contêineres:
   ```
   docker-compose up -d --build
   ```

## Uso

Após a inicialização dos contêineres, o OpenVAS estará acessível através da interface web do GSA no endereço `http://localhost:9392`.

O script Python `main.py` é executado a cada hora pelo cron job no container `gvmd`. Ele gera um relatório de varredura em formato XML, converte-o para CSV e envia para a API do GAT Core.

## Estrutura de Arquivos

- `docker-compose.yml`: Arquivo de configuração do Docker Compose.
- `Dockerfile.gvmd`: Dockerfile para construir a imagem personalizada do `gvmd`.
- `src/main.py`: Script Python para gerar e enviar relatórios de varredura.

## Limpeza

Para parar e remover todos os contêineres e volumes criados pelo Docker Compose, execute:
```
docker-compose down -v
```

## Notas

- Certifique-se de substituir os valores das variáveis de ambiente no arquivo `.env` pelas suas credenciais e URLs corretas.
- O script `main.py` está configurado para ser executado em um ambiente específico. Você pode precisar ajustá-lo para atender às suas necessidades.
