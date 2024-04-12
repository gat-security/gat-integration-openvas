import os
import sys
import csv
import json
import hashlib
import warnings
import requests as requests
import defusedxml.ElementTree as Et
import traceback
import py7zr
import time
import gc

from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings("ignore")

# Fazer o parse e armazenar todas as vulnerabilidades em um dictionary
def process_vulnerabilities(xml_file):
    vulnerabilities = {}

    with open(xml_file, 'rb') as file:
        context = Et.iterparse(file, events=('start', 'end'))
        _, root = next(context)
        for event, element in context:
            if event == 'end' and element.tag == 'vulnerability':
                vuln_id = element.get('id')
                vuln_data = parse_element(element)
                vulnerabilities[vuln_id] = vuln_data
                root.clear()

    return vulnerabilities


# Fazer o parse de forma recursiva, independente da estrutura do XML
def parse_element(elem):
    data = {'attributes': elem.attrib}
    if len(elem) == 0:
        data['text'] = elem.text
    else:
        data['children'] = []
        for child in elem:
            child_data = parse_element(child)
            data['children'].append({child.tag: child_data})
    return data


# Extrair os dados do nó "solution" independente da estrutura apresentada
def extract_solution_data(data):
    result = ""
    if isinstance(data, dict):
        for dk, dv in data.items():
            if dk == "text" or dk == "LinkURL":
                if dv is not None and dv != "":
                    result += dv + " "
            else:
                result += extract_solution_data(dv) + " "
    elif isinstance(data, list):
        for item in data:
            result += extract_solution_data(item) + " "

    return result.strip()


def gat_importer(filename, connection, script_path, on_premise, active_tags_list, allow_list_flag, max_vulnerabilities, max_vulnerabilities_per_file):

    print("Is on premise? {}".format(on_premise))
    print("GAT URL: {}".format(connection.gat_url))

    if on_premise:
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    file_path = script_path + 'xmls/' + filename + '.xml'

    delete_old_files(script_path + 'xmls/')
    delete_old_files(script_path + 'csvs/')

    vulnerabilities = process_vulnerabilities(file_path)

    hora_log = str(datetime.now()).replace(":", "-").replace(" ", "T")
    log_file = open(script_path + "import_logs/log_{}{}.txt".format(filename, hora_log), "a", newline='')

    #Template do nome do arquivo, para numerarmos os arquivos gerados
    template_file_and_path = script_path + 'csvs/' + filename + '_{}'
    current_csv_number = 1

    #Nomes dos arquivos atual no loop. Quando vários CSV's são gerados, iremos alterar a numeração dos arquivos
    current_file_and_path = template_file_and_path.format(current_csv_number) + ".csv"

    #Array com todos os nomes dos arquivos gerados
    all_files_and_paths = [{'file': current_file_and_path, 'issues': 0}]

    output_file = open(current_file_and_path, "a", newline='', encoding="utf-8")
    writer = csv.writer(output_file, delimiter=';', quoting=csv.QUOTE_ALL)

    # TODO : Parser e Conversão de arquivos XML
    print("Iniciando NexposeReport...")

    version = ''
    ref_header_titulo = ['REFERENCE TITLE 1', 'REFERENCE TITLE 2', 'REFERENCE TITLE 3', 'REFERENCE TITLE 4',
                         'REFERENCE TITLE 5',
                         'REFERENCE TITLE 6', 'REFERENCE TITLE 7', 'REFERENCE TITLE 8', 'REFERENCE TITLE 9',
                         'REFERENCE TITLE 10',
                         'REFERENCE TITLE 11', 'REFERENCE TITLE 12', 'REFERENCE TITLE 13', 'REFERENCE TITLE 14',
                         'REFERENCE TITLE 15',
                         'REFERENCE TITLE 16']

    ref_header_url = ['REFERENCE URL 1', 'REFERENCE URL 2', 'REFERENCE URL 3', 'REFERENCE URL 4', 'REFERENCE URL 5',
                      'REFERENCE URL 6', 'REFERENCE URL 7', 'REFERENCE URL 8', 'REFERENCE URL 9', 'REFERENCE URL 10',
                      'REFERENCE URL 11', 'REFERENCE URL 12', 'REFERENCE URL 13', 'REFERENCE URL 14',
                      'REFERENCE URL 15',
                      'REFERENCE URL 16']

    tag_header = ['TAG 1', 'TAG 2', 'TAG 3', 'TAG 4',
                  'TAG 5', 'TAG 6', 'TAG 7', 'TAG 8', 'TAG 9', 'TAG 10']

    issue = 0
    issue_fail = 0

    names_list = []
    allow_list_flag_bool = convert_allow_list_flag_to_bool(allow_list_flag)
    root_cause = "Rapid7 InsightVM"

    sev = [1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5]

    inside_nodes = False
    inside_node = False
    inside_fingerprint = False
    inside_endpoints = False
    inside_services = False
    inside_test = False

    # Variáveis utilizadas em cada node do XML, o conteúdo é resetado toda vez que entra em um novo node
    end_test_salvos = []
    operating_system = ""
    operating_system_list = []
    certainty_list = []
    certainty = ""
    address = ''
    name_list_node = ""

    # Variáveis utilizadas em cada test, o conteúdo é resetado toda vez que entra em um novo test
    port = "0"
    protocol = ""

    # Variáveis utilizadas em cada vulnerability, o conteúdo é resetado toda vez que entra em uma nova vulnerability
    malware_name = ""

    context = Et.iterparse(file_path, events=("start", "end"))

    current_vulnerability_number = 0
    current_vulnerability_per_file_number = 0
    started_new_target_count = 0

    for event_node, element_node in context:

        if element_node.tag == 'NexposeReport' and event_node == 'start':
            version = element_node.attrib['version']

        # Buscar os nós "nodes" e "node"
        if event_node == 'start':
            if inside_node and element_node.tag == 'name' and name_list_node == "" and element_node.text != None:
                names_list.append(element_node.text)
                name_list_node = element_node.text
            elif element_node.tag == 'nodes':
                inside_nodes = True
            elif element_node.tag == 'node':
                inside_node = True

                # Fazer o reset dos valores das variáveis toda vez que entrar em um node novo
                end_test_salvos = []
                operating_system = ""
                operating_system_list = []
                certainty_list = []
                certainty = ""
                name_list_node = ""

                if address != element_node.attrib['address']:
                    started_new_target_count = 0
                    address = element_node.attrib['address']

        elif event_node == 'end':
            if element_node.tag == 'nodes':
                inside_nodes = False
            elif element_node.tag == 'node':
                inside_node = False

        try:
            if inside_nodes and inside_node:
                # Obter as informações necessárias dentro de cada node
                # Fingerprints -> os
                if element_node.tag == 'fingerprints' and event_node == 'start':
                    inside_fingerprint = True
                elif element_node.tag == 'fingerprints' and event_node == 'end':
                    inside_fingerprint = False

                if inside_fingerprint:
                    if element_node.tag == 'os' and event_node == 'start':
                        # TODO: verificar se esse try/exept é necessário, pois logo abaixo ele sempre pega a última posição quando a versão == 2.0
                        try:
                            operating_system_list.append(element_node.attrib['product'])
                            certainty_list.append(element_node.attrib['certainty'])
                        except:
                            certainty = 0
                            operating_system = "Não Cadastrado"

                        try:
                            if version == "2.0":
                                operating_system = operating_system_list[0]
                                certainty = certainty_list[0]
                        except:
                            certainty = 0
                            operating_system = "Não Cadastrado"

                # Endpoints -> endpoint -> service
                if element_node.tag == 'endpoints':
                    if event_node == 'start':
                        inside_endpoints = True
                    elif event_node == 'end':
                        inside_endpoints = False
                elif inside_endpoints and element_node.tag == 'endpoint':
                    if event_node == 'start':
                        port = element_node.attrib['port']
                        protocol = element_node.attrib['protocol']
                elif inside_endpoints and element_node.tag == 'services':
                    if event_node == 'start':
                        inside_services = True
                    elif event_node == 'end':
                        inside_services = False
                elif inside_services and element_node.tag == 'service':
                    if event_node == 'start':
                        inside_service = True
                    elif event_node == 'end':
                        inside_service = False
                elif element_node.tag == 'test': #inside_service and
                    if 'status' in element_node.attrib and element_node.attrib['status'] != "not-vulnerable" and not element_node.attrib['id'] in end_test_salvos:
                        # O teste deve ser analisado apenas quando o status for diferente de "not-vulnerable", por isso a condição no if acima
                        # Também só deverá entrar se o test não tiver sido analisado ainda, isso é controlado com o array de id's de tests analisados
                        if event_node == 'start':
                            inside_test = True
                        elif event_node == 'end':
                            inside_test = False

                if inside_test and event_node == 'start' and element_node.tag == 'test':
                    # Procurar a vulnerabilidade desse teste

                    if element_node.attrib['id'] in vulnerabilities and (max_vulnerabilities == 0 or current_vulnerability_number < max_vulnerabilities):
                        current_vulnerability_number += 1

                        if(max_vulnerabilities_per_file > 0 and current_vulnerability_per_file_number >= max_vulnerabilities_per_file and started_new_target_count == 0):
                            all_files_and_paths[current_csv_number - 1]['issues'] = current_vulnerability_per_file_number
                            current_vulnerability_per_file_number = 0
                            current_csv_number += 1
                            current_file_and_path = template_file_and_path.format(current_csv_number) + ".csv"
                            all_files_and_paths.append({'file': current_file_and_path, 'issues': 0})
                            output_file = open(current_file_and_path, "a", newline='', encoding="utf-8")
                            writer = csv.writer(output_file, delimiter=';', quoting=csv.QUOTE_ALL)

                        current_vulnerability_per_file_number += 1

                        test_vulnerability = vulnerabilities[element_node.attrib['id']]

                        # Reset das variaveis utilizadas dentro do vulnerability
                        exploit_id = ""
                        exploit_title = ""
                        description = ""
                        tags_list = []
                        tags = ""
                        solution = ""
                        reference_title = []
                        reference_url = []

                        for vuln_child in test_vulnerability['children']:
                            if 'description' in vuln_child:
                                try:
                                    for vuln_desc in vuln_child['description']['children'][0]['ContainerBlockElement']['children']:
                                        if 'Paragraph' in vuln_desc and 'text' in vuln_desc['Paragraph']:
                                            description += " " + vuln_desc['Paragraph']['text']
                                            description = description.replace("\n", "")
                                            description = description.replace("  ", " ")
                                            description = description.replace('"', " ").strip()
                                except (KeyError, IndexError, TypeError):
                                    pass

                            elif 'tags' in vuln_child:
                                try:
                                    for vuln_tag in vuln_child['tags']['children']:
                                        if 'tag' in vuln_tag and 'text' in vuln_tag['tag']:
                                            # Checa a regra da tag para ver se ela pode ser adicionada
                                            if check_tags_rules(active_tags_list, allow_list_flag_bool, vuln_tag['tag']['text']) == False:
                                                tags_list.append("")
                                            else:
                                                # Substring if the value lenght is greater than 500 chars
                                                if len(vuln_tag['tag']['text']) > 500:
                                                    tags_list.append(vuln_tag['tag']['text'][:500])
                                                else:
                                                    tags_list.append(str(vuln_tag['tag']['text']))
                                except (KeyError, IndexError, TypeError):
                                    pass

                            elif 'solution' in vuln_child:
                                try:
                                    solution = extract_solution_data(vuln_child['solution']['children']).replace("	", "").replace("  ", "").replace("\n", "").strip()
                                except (KeyError, IndexError, TypeError):
                                    pass

                            elif 'references' in vuln_child and 'children' in vuln_child['references']:
                                try:
                                    for vuln_ref in vuln_child['references']['children']:
                                        if vuln_ref['reference']['attributes']['source'] == "URL":
                                            reference_url.append(vuln_ref['reference']['text'])
                                            if vuln_ref['reference']['text'].split("/")[-1] == "":
                                                reference_title.append(vuln_ref['reference']['text'].split("/")[-2])
                                            else:
                                                reference_title.append(vuln_ref['reference']['text'].split("/")[-1])
                                except (KeyError, IndexError, TypeError):
                                    pass

                            elif 'malware' in vuln_child and 'children' in vuln_child['malware']:
                                try:
                                    malware_name = ""
                                    if check_tags_rules(active_tags_list, allow_list_flag_bool, str(vuln_child['malware']['children'][0]['name']['text'])):
                                        malware_name = vuln_child['malware']['children'][0]['name']['text']
                                except (KeyError, IndexError, TypeError):
                                    pass

                            elif 'exploits' in vuln_child and 'children' in vuln_child['exploits']:
                                try:
                                    for vuln_exploit in vuln_child['exploits']['children']:
                                        for vuln_exploit_attr_key, vuln_exploit_attr_val in vuln_exploit['exploit']['attributes'].items():
                                            # exploit += vuln_exploit_attr_key + ": " + vuln_exploit_attr_val + ", "
                                            # exploits = exploit + '| '

                                            if vuln_exploit_attr_key == "id":
                                                if check_tags_rules(active_tags_list, allow_list_flag_bool, str(vuln_exploit_attr_val)):
                                                    exploit_id += vuln_exploit_attr_val + ", "
                                            elif vuln_exploit_attr_key == "title":
                                                if check_tags_rules(active_tags_list, allow_list_flag_bool, str(vuln_exploit_attr_val)):
                                                    exploit_title += vuln_exploit_attr_val + ", "
                                except (KeyError, IndexError, TypeError):
                                    pass

                        if solution is None or solution == "":
                            solution = "Sem solução cadastrada"

                        published_date = test_vulnerability['attributes']['published'].split('T')[0]
                        published_date = published_date[:4] + "-" + published_date[4:6] + "-" + published_date[6:]

                        added_date = test_vulnerability['attributes']['added'].split('T')[0]
                        added_date = added_date[:4] + "-" + added_date[4:6] + "-" + added_date[6:]

                        modified_date = test_vulnerability['attributes']['modified'].split('T')[0]
                        modified_date = modified_date[:4] + "-" + modified_date[4:6] + "-" + modified_date[6:]

                        end_test_salvos.append(element_node.attrib['id'])
                        test_status = ''

                        if check_tags_rules(active_tags_list, allow_list_flag_bool, str(element_node.attrib['status'])):
                            # TODO: verificar se é necessário colocar um else para definir algum status do teste quando a condição for falsa
                            test_status = element_node.attrib['status']

                        if version == "2.0":
                            cvss_score_tag = ""
                            if check_tags_rules(active_tags_list, allow_list_flag_bool, str(test_vulnerability['attributes']['cvssScore'])):
                                # TODO: verificar se é necessário colocar um else para definir algum cvss_score_tag do teste quando a condição for falsa
                                cvss_score_tag = test_vulnerability['attributes']['cvssScore']

                            risk_score = ""
                            if check_tags_rules(active_tags_list, allow_list_flag_bool, str(test_vulnerability['attributes']['riskScore'])):
                                risk_score = test_vulnerability['attributes']['riskScore']

                            header = ['address', 'port', 'protocol', 'os', 'certainty', 'test_status', 'id',
                                      'title', 'severity',
                                      'cvssScore', 'malware', 'exploit_id', 'exploit_title', 'published', 'added',
                                      'modified', 'riskScore', 'description',
                                      'tags', 'solution', 'hostname', 'netbios', 'root_cause']

                            for ref in range(len(ref_header_url)):
                                header.append(ref_header_titulo[ref])
                                header.append(ref_header_url[ref])

                            for tag in tag_header:
                                header.append(tag)

                            data = [address, port, protocol, operating_system,
                                    certainty, test_status, test_vulnerability['attributes']['id'],
                                    test_vulnerability['attributes']['title'],
                                    sev[int(test_vulnerability['attributes']['severity'])],
                                    cvss_score_tag,
                                    malware_name, exploit_id, exploit_title, published_date,
                                    added_date,
                                    modified_date,
                                    risk_score, description, tags,
                                    solution, name_list_node, name_list_node, root_cause]

                            for ref in range(len(reference_url)):
                                data.append(reference_title[ref])
                                data.append(reference_url[ref])

                            diff = len(ref_header_titulo) - len(reference_url)
                            diff *= 2
                            index = 1
                            tags_index = 0
                            tags_list_length = len(tags_list) + 1
                            while index < diff + tags_list_length:
                                if index > diff:
                                    data.append(tags_list[tags_index])
                                    tags_index += 1
                                else:
                                    data.append("")
                                index += 1

                            if ":" not in address:
                                if os.path.getsize(current_file_and_path) == 0 and started_new_target_count == 0:
                                    writer.writerow(header)
                                writer.writerow(data)
                                issue += 1
                            else:
                                log_file.write(
                                    "\tApontamento não cadastrado '{} porta:{} - {} | Severidade: {}' -> IPv6\n".format(
                                        address, port, test_vulnerability['attributes']['id'],
                                        sev[int(test_vulnerability['attributes']['severity'])]))
                                issue_fail += 1

                        elif version == "1.0":
                            cvss_score_tag = ""
                            if check_tags_rules(active_tags_list, allow_list_flag_bool, str(test_vulnerability['attributes']['cvssScore'])) == True:
                                cvss_score_tag = test_vulnerability['attributes']['cvssScore']

                            header = ['address', 'port', 'protocol', 'os', 'certainty', 'test_status', 'id',
                                      'title', 'severity',
                                      'cvssScore', 'malware', 'exploit_id', 'exploit_title', 'published', 'added',
                                      'modified', 'riskScore', 'description',
                                      'tags', 'solution', 'hostname', 'netbios', 'root_cause']

                            for ref in range(len(ref_header_url)):
                                header.append(ref_header_titulo[ref])
                                header.append(ref_header_url[ref])

                            for tag in tag_header:
                                header.append(tag)

                            data = [address, port, protocol, "Sistema Operacional não cadastrado",
                                    "", test_status, test_vulnerability['attributes']['id'],
                                    test_vulnerability['attributes']['title'],
                                    sev[int(test_vulnerability['attributes']['severity'])],
                                    cvss_score_tag, '', '',
                                    '',
                                    published_date,
                                    added_date,
                                    modified_date, "", description, tags,
                                    solution, name_list_node, name_list_node, root_cause]

                            for ref in range(len(reference_url)):
                                data.append(reference_title[ref])
                                data.append(reference_url[ref])

                            diff = len(ref_header_titulo) - len(reference_url)
                            diff *= 2
                            index = 1
                            tags_index = 0
                            tags_list_length = len(tags_list) + 1
                            while index < diff + tags_list_length:
                                if index > diff:
                                    data.append(tags_list[tags_index])
                                    tags_index += 1
                                else:
                                    data.append("")
                                index += 1

                            if ":" not in address:
                                if os.path.getsize(current_file_and_path) == 0 and started_new_target_count == 0:
                                    writer.writerow(header)
                                writer.writerow(data)
                                issue += 1
                            else:
                                log_file.write(
                                    "\tApontamento não cadastrado '{} porta:{} - {} | Severidade: {}' -> IPv6\n".format(
                                        address, port, test_vulnerability['attributes']['id'],
                                        sev[int(test_vulnerability['attributes']['severity'])]))
                                issue_fail += 1

                        started_new_target_count += 1
        except:
            traceback.print_exc()

    all_files_and_paths[current_csv_number - 1]['issues'] = current_vulnerability_per_file_number

    for fp in all_files_and_paths:
        print("Total NexposeReport (" + filepath + "):", fp['issues'])

    log_file.write("\n\tApontamentos convertidos: {}".format(issue))

    if issue_fail > 0:
        log_file.write("\n\tApontamentos não convertidos: {}\n\n".format(issue_fail))

    #Liberar uso de memoria
    output_file.close()
    vulnerabilities = None
    end_test_salvos = []
    operating_system = ""
    operating_system_list = []
    certainty_list = []
    certainty = ""
    address = ''
    name_list_node = ""
    context = None
    names_list = []

    del operating_system_list
    del operating_system
    del certainty
    del certainty_list
    del name_list_node
    del address
    del names_list
    del context
    del vulnerabilities
    del end_test_salvos
    del output_file
    del writer

    gc.collect()

    return all_files_and_paths, version

def get_xml_hash(filename, script_path):
    return hashlib.sha256(open(script_path + "xmls/" + filename + '.xml', 'rb').read()).hexdigest()


def check_xml_hash(filename, script_path, company_id, csv_path):
    control_dict = {}

    # Pega o hash da integridade do arquivo gerado
    # para comparar com o ultimo hash salvo no json de controle
    xml_hash = get_xml_hash(filename, script_path)

    with open(script_path + company_id + '.json') as file:
        control_dict = json.load(file)

        if xml_hash == control_dict['lastHash']:
            if os.path.exists(csv_path):
                os.remove(csv_path)

            os.remove(script_path + 'xmls/' + filename + '.xml')
            print("success")
            sys.exit(0)


def write_xml_hash(filename, script_path, company_id):
    xml_hash = get_xml_hash(filename, script_path)

    control_dict = {}

    if os.path.exists(script_path + company_id + '.json'):
        os.remove(script_path + company_id + '.json')

    # Atribui o hash da integridade do arquivo xml ao lastHash do control Json
    with open(script_path + company_id + '.json', 'w') as outfile:
        control_dict['lastHash'] = xml_hash
        json_object = json.dumps(control_dict, indent=4)
        outfile.write(json_object)


# Retorna True se a TAG pode ser adicionada a lista de tags. False se não puder.
def check_tags_rules(active_tags_list, allow_list_flag_bool, tag):
    # Checa se a lista está vazia.
    # A lista estará vazia se o usuário não mapeou nenhuma Tag no Allow ou Deny List
    if not active_tags_list:
        return True

    # Checa se o usuário escolheu entre Allow List ou Deny List para aplicar a respectiva regra
    # Se ele escolheu Allow List, o valor do allow_list_flag_bool será True.
    if allow_list_flag_bool == True:
        # Quando for True, devemos ver se a TAG está na lista do active_tags_list.
        # Se estiver, nós podemos adiciona-la, pois a regra é de Allow List.
        for allow_tag in active_tags_list:
            if str(allow_tag).lower().strip() == str(tag).lower().strip():
                return True

        return False

    # Checa se o usuário escolheu entre Allow List ou Deny List para aplicar a respectiva regra
    # Se ele escolheu Deny List, o valor do allow_list_flag_bool será False.
    if allow_list_flag_bool == False:
        # Quando for False, devemos ver se a TAG está na lista do active_tags_list.
        # Se estiver, nós não podemos adiciona-la, pois a regra é de Deny List.
        for deny_tag in active_tags_list:
            if str(deny_tag).lower().strip() == str(tag).lower().strip():
                return False

        return True


def convert_allow_list_flag_to_bool(allow_list_flag):
    if str(allow_list_flag) == 'true':
        return True

    if str(allow_list_flag) == 'false':
        return False


def compress_csv(input_file, output_file):
    try:
        with py7zr.SevenZipFile(output_file, 'w') as archive:
            archive.writeall(input_file, os.path.basename(input_file))
            print("Sucesso na compressão: {}".format(output_file))
            return True
    except Exception as e:
        print("Erro genérico na compressão: {}".format(e))
        return False


def delete_old_files(directory):
    extensions_to_delete = ['.csv', '.xml', '.zip', '.7z']

    # Apagar apenas arquivos mais antigos que 24h atrás
    time_threshold = time.time() - (24 * 3600)

    for root, _, files in os.walk(directory):
        for file in files:
            _, ext = os.path.splitext(file)
            if ext.lower() in extensions_to_delete:
                complete_path = os.path.join(root, file)

                if os.path.getmtime(complete_path) < time_threshold:
                    os.remove(complete_path)

    print("Arquivos antigos apagados no diretorio {}".format(directory))


def check_if_scan_is_finished(connection, bearer, scan_id, is_onpremise):
    with requests.Session() as s:
        s.headers = {
            'Authorization': 'Bearer %s' % bearer,
            'cache-control': "no-cache"
        }

    url = connection.gat_url
    protocol = "https"
    if "localhost" in url:
        protocol = "http"
        resource = '/vulnerability/scan/findById?id={}'.format(scan_id)
    else:
        protocol = "https"
        resource = '/app/vulnerability/scan/findById?id={}'.format(scan_id)

    endpoint_api = "{}://{}{}".format(protocol, url, resource)

    if is_onpremise:
        proxies = {"http": "", "https": ""}
        r = s.request('GET', endpoint_api, verify=not is_onpremise, proxies=proxies)
    else:
        r = s.request('GET', endpoint_api, verify=not is_onpremise)
    response = json.loads(r.text)
    print("Resultado check Scan ID {} | Status: {}".format(response['id'], response['status']))

    return response


def upload_all_scan_files(connection, version, filename, script_path, filepath, on_premise, company_id):

    hora_log = str(datetime.now()).replace(":", "-").replace(" ", "T")
    log_file = open(script_path + "log_{}{}.txt".format(filename, hora_log), "a", newline='')

    url = connection.gat_url
    bearer = connection.gat_token
    resource = '/app/vulnerability/upload/api/Rapid7/'
    resources = connection.custom_parser_name
    
    protocol = "https"
    if "localhost" in url:
        protocol = "http"
        if version == "2.0":
            resource = '/vulnerability/upload/api/{}/?decompress=true'.format(resources)
        else:
            resource = '/vulnerability/upload/api/{}/?decompress=true'.format(resources)
    else:
        protocol = "https"
        if version == "2.0":
            resource = '/app/vulnerability/upload/api/{}/?decompress=true'.format(resources)
        else:
            resource = '/app/vulnerability/upload/api/{}/?decompress=true'.format(resources)


    # Export Custom Parser
    gat_point = "{}://{}{}".format(protocol, url, resource)

    try:
        # Se o arquivo json existir, significa que não é a primeira execução
        # Código desativado para não excluir o XML mesmo que não tenha sido o primeiro processamento,
        # pode ter ocorrido algum erro na geração do CSV
        # if os.path.exists(script_path + company_id + '.json'):
        #     check_xml_hash(filename, script_path, company_id, file_and_path)

        scan_upload_max_number_of_retries = 3
        scan_upload_current_try = 0
        scan_is_finished = False
        upload_response_text = ""

        while scan_is_finished is False:
            try:
                print("Tentativa {} de {} para o upload do scan".format(scan_upload_current_try, scan_upload_max_number_of_retries))

                file_and_path_compressed = filepath.replace(".csv", ".7z")
                if compress_csv(filepath, file_and_path_compressed):
                    print("\nIniciando exportação do arquivo '{}'".format(file_and_path_compressed))
                    with open(file_and_path_compressed, "rb") as export_file:
                        export_file_name = os.path.basename(file_and_path_compressed)
                        file_dict = {'file': (export_file_name, export_file,
                                                "application/x-7z-compressed", {'Expires': "0"})}
                        with requests.Session() as s:
                            s.headers = {
                                'Authorization': 'Bearer %s' % bearer,
                                'cache-control': "no-cache"
                            }

                        if on_premise:
                            proxies = {"http": "", "https": ""}
                            r = s.request('POST', gat_point, files=file_dict, verify=not on_premise, proxies=proxies)
                        else:
                            r = s.request('POST', gat_point, files=file_dict, verify=not on_premise)

                        upload_response_text = r.text
                        response = json.loads(r.text)
                        print(response)
                        print("Scan ID gerado: {}".format(response['scan_id']))
                        print("{} - {}".format(datetime.now().strftime("%Y-%m-%d-%I:%M:%S"), response))
                        log_file.write("\t\t{} - {}\n".format(datetime.now().strftime("%Y-%m-%d-%I:%M:%S"), response))

                        time_to_wait = 15 #Em segundos
                        count_max_sleep = 30 #Quantidade de vezes máximas que o código pode dormir
                        count_current_sleep = 0
                        while scan_is_finished is False:
                            scan_check = check_if_scan_is_finished(connection, bearer, response['scan_id'], on_premise)
                            if scan_check['status'] == "COMPLETED" or scan_check['status'] == "ERROR":
                                scan_is_finished = True
                            else:
                                print("Vamos aguardar {} segundos para verificar o status do scan".format(time_to_wait))
                                time.sleep(time_to_wait)
                            count_current_sleep += 1

                            if count_current_sleep > count_max_sleep:
                                print("Aguardamos {} vezes o scan completar, sem sucesso, vamos continuar para a próxima exportação".format(count_current_sleep))
                                break

                        if os.path.exists(script_path + 'xmls/' + filename + '.xml'):
                            write_xml_hash(filename, script_path, company_id)
                            os.remove(script_path + 'xmls/' + filename + '.xml')

                        #if os.path.exists(filepath):
                        #    os.remove(filepath)

                        if os.path.exists(file_and_path_compressed):
                            os.remove(file_and_path_compressed)
                else:
                    raise Exception("Erro na compressão do arquivo CSV")
            except Exception as e:
                print("{} - Upload Error: {}".format(datetime.now().strftime(
                    "%Y-%m-%d-%I:%M:%S"
                ), e))
                print("Retorno do upload: {}".format(upload_response_text))
                log_file.write("\t\t{} - Upload Error: {}\n".format(datetime.now().strftime(
                    "%Y-%m-%d-%I:%M:%S"
                ), e))
                print(traceback.format_exc())

            scan_upload_current_try += 1
            if scan_upload_current_try > scan_upload_max_number_of_retries:
                scan_is_finished = True

        print("Upload e verificação do Scan confirmado, vamos aguardar 120 segundos antes de iniciarmos o próximo")
        time.sleep(120)

    except Exception as e:
        print("{} - Upload Error: {}".format(datetime.now().strftime(
            "%Y-%m-%d-%I:%M:%S"
        ), e))
        log_file.write("\t\t{} - Upload Error: {}\n".format(datetime.now().strftime(
            "%Y-%m-%d-%I:%M:%S"
        ), e))
        print(traceback.format_exc())
    print("\n")

    if os.path.exists(script_path + 'xmls/' + filename + '.xml'):
        os.remove(script_path + 'xmls/' + filename + '.xml')

