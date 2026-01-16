# Integração GAT Scan com priorização- GAT Core x Greenbone Community (antigo Openvas) 

Este projeto configura e executa o Greenbone Community Edition usando Docker. Ele inclui todos os serviços necessários para executar o Greenbone Community Edition, bem como integrar o resultado ao GAT Core e auxiliando na priorização das vulnerabilidades com dados do EPSS v3.

## Contexto
**GAT Core:** GAT Core é uma plataforma de gerenciamento de vulnerabilidades cibernéticas que centraliza e prioriza informações de segurança, facilitando a gestão e mitigação de riscos. Ele oferece uma visão holística da segurança da informação, contribuindo para a construção da melhor estratégia e apresentação de resultados.

**Greenbone Community Edition (antigo Openvas):** É uma scanner de vulnerabilidades de código aberto. Ele realiza varreduras abrangentes em redes, identificando possíveis falhas de segurança. A Greenbone Community Edition é amplamente utilizada por sua capacidade de detecção precisa e sua flexibilidade em ambientes diversos.

**EPSS v3 (Exploit Prediction Scoring System):** É uma métrica que avalia a probabilidade de uma vulnerabilidade ser explorada em ataques no mundo real. Utilizando dados de ameaças e técnicas avançadas de machine learning, o EPSS fornece insights valiosos que ajudam as organizações a priorizarem as vulnerabilidades que representam maiores riscos.

## Benefícios da Integração
A integração do GAT Core com o Greenbone Community Edition e a inclusão de dados do EPSS v2 traz diversos benefícios:

- **Centralização de Informações:** Consolidar os resultados das varreduras de vulnerabilidades em uma única plataforma facilita a gestão e o acompanhamento das ações corretivas.
- **Priorização Inteligente:** Utilizando o EPSS v2, o GAT Core pode reclassificar as vulnerabilidades com base na probabilidade de exploração, permitindo que as equipes de segurança foquem nas ameaças mais críticas.
- **Automatização:** A integração permite a execução automática de varreduras e a geração de relatórios, economizando tempo e reduzindo o esforço manual.

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
- GAT_URL: Url do ambiente do GAT Core. Caso queira executar local usar: http://host.docker.internal:8080.
- GAT_TOKEN: Token para integração com o GAT Core sem o Bearer (https://www.gatinfosec.com/central-de-suporte/api-gat-core/)
- ONPREMISE: True ou False para GAT Core na versão On premise
- SCHEDULE_TYPE: Frequência de execução do scan (Once, Hourly, Daily, Weekly, Monthly, Yearly)
- SCHEDULE_TIME: Horário da execução
- SCHEDULE_FIRST_DATE: Data da primeira execução (Ano-mês-dia). Ex. 2024-04-01
- TIMEZONE: Horário mundial Ex.:America/Sao_Paulo
- QOD: Descreve a confiabilidade da detecção de vulnerabilidade executada ou detecção de produto. (https://docs.greenbone.net/GSM-Manual/gos-20.08/en/reports.html#quality-of-detection-concept)
- EXECUTE_NOW: se executará o scanner logo após concluir a configuração
- EPSS: define se utilizará o EPSS para reclassificar a vulnerabilidade
- GREENBONE_HOSTS_FILE: Define o arquivo hosts usado para definir os targets no scan.
- ASSETS_PAGE_SIZE: Define a quantidade de asserts baixados por vez.

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
   EPSS=True
   ```

4. Construa e inicie os contêineres:
   ```sh
   docker compose --env-file .env.example -f docker-compose.yml -p greenbone-community-edition up -d --build

   docker compose -f docker-compose.yml -p greenbone-community-edition exec -u gvmd gvmd gvmd --user=admin --new-password='password'

   docker compose -f docker-compose.yml -p greenbone-community-edition exec -u gvmd gvmd python3 app/configure.py
   ```
   > Substituir o "password" pela senha a mesma senha do .env

5. Caso seja necessário reiniciar os containers
   ```sh
   docker compose -f docker-compose.yml -p greenbone-community-edition restart
   ```

6. Em caso de necessidade de atualizar os containers
   ```sh
   docker compose -f docker-compose.yml -p greenbone-community-edition pull

   docker compose -f docker-compose.yml -p greenbone-community-edition up -d
   ```
## Execução
É preciso criar um cronjob ou tarefa agendada para executar o comando abaixo, aconselhamos registrar a execução a cada 1 hora. Ele gera um relatório em CSV e envia para a API do GAT Core.
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
- `src/epss/epss.csv`: Arquivo CSV com dados EPSS para reclassificação de vulnerabilidades.

## Notas

- Certifique-se de substituir os valores das variáveis de ambiente no arquivo `.env` pelas suas credenciais e URLs corretas.

## Conheça a GAT InfoSec

https://gatinfosec.com
