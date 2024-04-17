import os
import sys
import csv
import json
import hashlib
import warnings
import requests as requests
import traceback
import py7zr
import time

from datetime import datetime

warnings.filterwarnings("ignore")


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
                        count_max_sleep = 10 #Quantidade de vezes máximas que o código pode dormir
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

                        if os.path.exists(filepath):
                            os.remove(filepath)

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

