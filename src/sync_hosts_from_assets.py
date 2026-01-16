import os
import json
import traceback
import requests as requests
from urllib.parse import urlparse


def sync_hosts_from_assets(connection, hosts_file_path="/app/hosts", page_size=30, on_premise=False):
    """
    Busca /api/v2/assets paginado, filtra type=HOST, coleta IPs e grava um IP por linha em hosts_file_path.
    """
    on_premise = str(on_premise).lower() == "true"
    bearer = connection.gat_token
    url = (connection.gat_url or "").strip().rstrip("/")

    # Mesmo padrão do upload_all_scan_files (assume http se vier sem scheme)
    parsed = urlparse(url)
    if not parsed.scheme:
        base = "http://" + url
        parsed = urlparse(base)
    else:
        base = url

    host = parsed.netloc          # ex: "localhost:8080"
    scheme = parsed.scheme        # "http" ou "https"

    # endpoint base (sem /app) igual ao curl que você mandou
    assets_base = f"{scheme}://{host}/api/v2/assets"

    print("Assets endpoint base:", assets_base)

    ips = set()
    upload_response_text = ""

    try:
        page = 0
        while True:
            endpoint = f"{assets_base}?size={page_size}&page={page}"
            print(f"Buscando assets: page={page} size={page_size}")

            with requests.Session() as s:
                s.headers = {
                    'Authorization': 'Bearer %s' % bearer,
                    'cache-control': "no-cache",
                    'Accept': "application/json",
                    'Content-Type': "application/json"
                }

                if on_premise:
                    proxies = {"http": "", "https": ""}
                    r = s.request('GET', endpoint, verify=not on_premise, proxies=proxies)
                else:
                    r = s.request('GET', endpoint, verify=not on_premise)

            if r.status_code == 204:
                print("Assets retornou 204 (No Content). Encerrando paginação.")
                break

            if r.status_code >= 400:
                raise Exception(f"Erro HTTP {r.status_code} ao consultar assets: {r.text}")

            upload_response_text = r.text

            try:
                data = r.json()
            except Exception:
                raise Exception(f"Resposta do assets não é JSON (HTTP {r.status_code}): {r.text}")

            content = data.get("content") or []
            if not content:
                print("Página vazia, encerrando paginação.")
                break

            # coleta IPs de HOST
            for item in content:
                if not isinstance(item, dict):
                    continue
                if str(item.get("type", "")).upper() != "HOST":
                    continue

                ip = None
                host_obj = item.get("host")
                if isinstance(host_obj, dict):
                    ip = host_obj.get("ip")

                if not ip:
                    ip = item.get("key")

                if ip:
                    ip = str(ip).strip()
                    if ip:
                        ips.add(ip)

            page += 1
        print("Iniciando gravação dos hosts no arquivo. {}".format(ips))
        existing = set()
        if os.path.exists(hosts_file_path):
            with open(hosts_file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        existing.add(line)

        merged = existing | ips

        os.makedirs(os.path.dirname(hosts_file_path) or ".", exist_ok=True)
        tmp_path = hosts_file_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            for ip in sorted(merged):
                f.write(ip + "/32" + "\n")
        os.replace(tmp_path, hosts_file_path)

        print(f"Arquivo hosts gerado com sucesso: {hosts_file_path} ({len(ips)} IPs)")

    except Exception as e:
        print("{} - Sync Hosts Error: {}".format(__import__("datetime").datetime.now().strftime("%Y-%m-%d-%I:%M:%S"), e))
        print("Retorno da chamada assets: {}".format(upload_response_text))
        print(traceback.format_exc())
        raise
