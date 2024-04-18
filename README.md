# Greenbone Community Edition Docker Compose

Este projeto configura e executa o Greenbone Community Edition usando Docker. Ele inclui todos os serviços necessários para executar o Greenbone Community Edition, bem como integra o resultado ao GAT Core.

## Pré-requisitos

- Docker (https://docs.docker.com/engine/install/)
- Docker Compose (https://docs.docker.com/compose/install/)

### Recomendado
- CPU Cores: 4
- Random-Access Memory: 8Gb
- Hard Disk: 60Gb

## Documentação do Greenbone Community (antigo Openvas)
https://greenbone.github.io/docs/latest/22.4/container/index.html

## Instalação e Configuração

1. Clone este repositório:
   ```sh
   git clone https://github.com/gat-security/gat-integration-openvas
   cd gat-integration-openvas
   ```
   
2. Defina o escopo dentro do arquivo `src/hosts`
   ```
   192.169.10.0/24
   192.168.5.10
   ```

3. Defina as variáveis de ambiente necessárias no arquivo `.env` na raiz do projeto:

- OPENVAS_USERNAME: Usuário do Greenbone Community. Default: admin
- OPENVAS_PASSWORD: Senha a ser configurada no Greenbone Community 
- GAT_URL: Url do ambiente do GAT Core
- GAT_TOKEN: Token para integração com o GAT Core sem o Bearer (https://www.gatinfosec.com/central-de-suporte/api-gat-core/)
- ONPREMISE: True ou False para GAT Core na versão On premise
- SCHEDULE_TYPE: Frequência de execução do scan (Once, Hourly, Daily, Weekly, Monthly, Yearly)
- SCHEDULE_TIME: Horário da execução
- SCHEDULE_FIRST_DATE: Data da primeira execução (Ano-mês-dia). Ex. 2024-04-01
- TIMEZONE: Horário mundial Ex.:America/Sao_Paulo
- QOD: Descreve a confiabilidade da detecção de vulnerabilidade executada ou detecção de produto. (https://docs.greenbone.net/GSM-Manual/gos-20.08/en/reports.html#quality-of-detection-concept)
- EXECUTE_NOW: se executará o scanner logo após concluir a configuração

   ```
   OPENVAS_USERNAME=admin
   OPENVAS_PASSWORD=your_password
   GAT_URL=https://your_gat_url
   GAT_TOKEN=your_gat_token
   ONPREMISE=False
   SCHEDULE_TYPE=Daily
   SCHEDULE_TIME=12:00
   SCHEDULE_FIRST_DATE=2024-04-01
   TIMEZONE=America/Sao_Paulo
   QOD=30
   EXECUTE_NOW=True
   ```

4. Construa e inicie os contêineres:
   ```sh
   docker compose -f docker-compose.yml -p greenbone-community-edition up -d --build

   docker compose -f docker-compose.yml -p greenbone-community-edition exec -u gvmd gvmd gvmd --user=admin --new-password='<password>'

   docker compose -f docker-compose.yml -p greenbone-community-edition exec gvmd python3 app/configure.py
   ```
   > Substituir o "password" pela senha a mesma senha do .env

5. Em caso de necessidade de atualizar os containers
   ```sh
   docker compose -f docker-compose.yml -p greenbone-community-edition pull

   docker compose -f docker-compose.yml -p greenbone-community-edition up -d
   ```
## Uso
É preciso criar um cronjob ou tarefa agendada para executar o comando abaixo, aconselhamos registrar a execução a cada 1 hora. Ele gera um relatório de varredura em formato XML, converte-o para CSV e envia para a API do GAT Core.
   ```sh
   docker compose -f docker-compose.yml -p greenbone-community-edition exec gvmd python3 app/main.py
   ```

## Estrutura de Arquivos

- `docker-compose.yml`: Arquivo de configuração do Docker Compose.
- `Dockerfile.gvmd`: Dockerfile para construir a imagem personalizada do `gvmd`.
- `.env`: Variáveis de ambiente para configuração da integração.
- `src/hosts`: Lista de redes ou IPs únicos.
- `src/configure.py`: Script Python para configurar o scanner de vulnerabilidade.
- `src/main.py`: Script Python para gerar e enviar relatórios de varredura.
- `src/csvs`: Pasta onde serão armazenados os arquivos csv de results do scanner de vulnerabilidade.
- `src/xmls`: Pasta onde serão armazenados os arquivos xml de results do scanner de vulnerabilidade.

## Notas

- Certifique-se de substituir os valores das variáveis de ambiente no arquivo `.env` pelas suas credenciais e URLs corretas.
