# Greenbone Community Edition Docker Compose

Este projeto configura e executa o Greenbone Community Edition usando Docker. Ele inclui todos os serviços necessários para executar o Greenbone Community Edition, bem como integra o resultado ao GAT Core.

## Pré-requisitos

- Docker
- Docker Compose

### Recomendado
- CPU Cores: 4
- Random-Access Memory: 8Gb
- Hard Disk: 60Gb

## Documentação para instalação do Greenbone Community
https://greenbone.github.io/docs/latest/22.4/container/index.html

## Configuração

1. Clone este repositório:
   ```sh
   git clone https://github.com/danilofranco/integra-openvas-gatcore.git
   cd integra-openvas-gatcore
   ```
   
2. Defina o escopo dentro do arquivo `hosts`
   ```
   192.169.10.0/24
   192.168.5.10
   ```

3. Defina as variáveis de ambiente necessárias no arquivo `.env` na raiz do projeto:

- GAT_SCAN_USERNAME: usuário do GAT Scan. Default: admin
- GAT_SCAN_PASSWORD: senha a ser configurada no GAT Scan 
- GAT_URL: url do ambiente do GAT Core
- GAT_TOKEN: token para integração com o GAT Core sem o Bearer (https://www.gatinfosec.com/central-de-suporte/api-gat-core/)
- ONPREMISE: True ou False para GAT Core na versão On premise
- SCHEDULE_TYPE: Frequência de execução do scan (Once, Hourly, Daily, Weekly, Monthly, Yearly)
- SCHEDULE_TIME: Horário da execução
- SCHEDULE_FIRST_DATE: Data da primeira execução (Ano-mês-dia). Ex. 2024-04-01
- TIMEZONE: horário mundial Ex.:America/Sao_Paulo


   ```
   GAT_SCAN_USERNAME=admin
   GAT_SCAN_PASSWORD=your_password
   GAT_URL=https://your_gat_url
   GAT_TOKEN=your_gat_token
   ONPREMISE=False
   SCHEDULE_TYPE=Daily
   SCHEDULE_TIME=12:00
   SCHEDULE_FIRST_DATE=2024-04-01
   TIMEZONE=America/Sao_Paulo
   ```

4. Construa e inicie os contêineres:
   ```sh
   docker compose -f docker-compose.yml -p greenbone-community-edition up -d --build

   docker compose -f docker-compose.yml -p greenbone-community-edition exec -u gvmd gvmd gvmd --user=admin --new-password='<password>'

   docker exec -it greenbone-community-edition-gvmd-1 python3 app/configure.py
   ```
   > Substituir o "password" pela senha a mesma senha do .env

5. Em caso de necessidade de atualizar os containers
   ```sh
   docker compose -f docker-compose.yml -p greenbone-community-edition pull

   docker compose -f docker-compose.yml -p greenbone-community-edition up -d
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
