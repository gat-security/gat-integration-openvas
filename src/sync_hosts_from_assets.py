import os
import traceback
import requests as requests
from urllib.parse import urlparse


def _parse_csv_ids(env_value: str):
    """
    Converte "id1,id2, id3" -> ["id1","id2","id3"] (ignorando vazios).
    """
    if not env_value:
        return []
    return [x.strip() for x in env_value.split(",") if x.strip()]
def _unwrap(value):
    if isinstance(value, tuple) and len(value) == 1:
        return value[0]
    return value

def sync_hosts_from_assets():
    """
    POST /api/v2/assets paginado, filtrando type=HOST e tags (FILTER_TAG_ID),
    coleta IPs e grava um IP/32 por linha em hosts_file_path.
    """
    hosts_file_path= _unwrap(os.getenv("GREENBONE_HOSTS_FILE", "/app/hosts"))
    page_size=int(os.getenv("ASSETS_PAGE_SIZE", "200")),
    on_premise = os.getenv('ONPREMISE')

    on_premise = str(on_premise).lower() == "true"
    bearer = os.getenv('GAT_TOKEN')
    url = (os.getenv('GAT_URL') or "").strip().rstrip("/")

    parsed = urlparse(url)
    if not parsed.scheme:
        parsed = urlparse("http://" + url)

    host = parsed.netloc
    scheme = parsed.scheme

    assets_base = f"{scheme}://{host}/api/v2/assets"


    tag_ids = _parse_csv_ids(os.getenv("FILTER_TAG_ID", ""))
    print(os.getenv("FILTER_TAG_ID", ""), tag_ids)
    filter_body = {"type": ["HOST"]}
    if tag_ids:
        filter_body["tags"] = tag_ids

    print(f"Assets endpoint base: {assets_base} filters: {filter_body}")

    ips = set()
    last_response_text = ""

    try:
        page = 0
        while True:
            endpoint = f"{assets_base}?size={page_size}&page={page}"
            print(f"Buscando assets: page={page} size={page_size} tags={len(tag_ids)}")

            with requests.Session() as s:
                s.headers = {
                    "Authorization": f"Bearer {bearer}",
                    "cache-control": "no-cache",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                }

                if on_premise:
                    proxies = {"http": "", "https": ""}
                    r = s.request(
                        "POST",
                        endpoint,
                        json=filter_body,
                        verify=not on_premise,
                        proxies=proxies,
                        timeout=120,
                    )
                else:
                    r = s.request(
                        "POST",
                        endpoint,
                        json=filter_body,
                        verify=not on_premise,
                        timeout=120,
                    )

            if r.status_code == 204:
                print("Assets retornou 204 (No Content). Encerrando paginação.")
                break

            if r.status_code >= 400:
                raise Exception(f"Erro HTTP {r.status_code} ao consultar assets: {r.text}")

            last_response_text = r.text

            try:
                data = r.json()
            except Exception:
                raise Exception(f"Resposta do assets não é JSON (HTTP {r.status_code}): {r.text}")

            content = data.get("content") or []
            if not content:
                print("Página vazia, encerrando paginação.")
                break

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

            if data.get("last") is True:
                print("Página marcada como last=true. Encerrando paginação.")
                break

            page += 1

        print(f"Iniciando gravação dos hosts no arquivo ({len(ips)} IPs novos).")

        existing = set()
        if os.path.exists(hosts_file_path):
            with open(hosts_file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        existing.add(line.replace("/32", ""))

        merged = existing | ips

        os.makedirs(os.path.dirname(hosts_file_path) or ".", exist_ok=True)
        with open(hosts_file_path, "w", encoding="utf-8") as f:
            for ip in sorted(merged):
                f.write(ip + "\n")

        print(f"Arquivo hosts atualizado: {hosts_file_path} (total {len(merged)} entradas)")

    except Exception as e:
        print("{} - Sync Hosts Error: {}".format(
            __import__("datetime").datetime.now().strftime("%Y-%m-%d-%I:%M:%S"), e
        ))
        print("Última resposta do assets:", last_response_text)
        print(traceback.format_exc())
        raise
