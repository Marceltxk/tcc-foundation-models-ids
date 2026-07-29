"""
rotulagem_cicids2017.py

Reconstroi a coluna "Label" para fluxos gerados pelo NFStream a partir dos
PCAPs originais da CICIDS2017, usando IP de origem, IP de destino e o
timestamp de inicio do fluxo (bidirectional_first_seen_ms).

As janelas de ataque (data, horario, atacante, vitima) foram retiradas
diretamente da pagina oficial do dataset:
https://www.unb.ca/cic/datasets/ids-2017.html (secao "Victim and attacker
networks information" + descricao dia a dia, terca a sexta-feira).

IMPORTANTE -- NAT do firewall:
O atacante (Kali) tem IP publico 205.174.165.73 (e as 3 maquinas do DDoS de
sexta tem 205.174.165.69-71), mas o proprio site do CIC documenta que esse
trafego passa por NAT no firewall antes de chegar na rede da vitima:
    205.174.165.73 -> 205.174.165.80 (firewall) -> 172.16.0.1 -> vitima
Ou seja: se o seu PCAP foi capturado dentro da rede interna (o que e o caso
quando todos os IPs que aparecem no CSV do NFStream sao da faixa 192.168.10.x
/ 192.168.10.3 etc.), o atacante vai aparecer como 172.16.0.1, e NAO como o
IP publico 205.174.165.73. Por isso as janelas abaixo incluem os dois IPs
como candidatos a atacante em cada ataque originado externamente (tudo, exceto
a segunda fase da Infiltration, que ja e um scan interno feito pela propria
maquina vitima).

Aviso metodologico:
Engelen, Rimmer & Joosen (2021), em "Troubleshooting an Intrusion Detection
Dataset: the CICIDS2017 Case Study", relatam que essas janelas oficiais nao
sao perfeitamente precisas e que os proprios autores do CICFlowMeter tiveram
que ajustar manualmente os horarios ate aproximar a contagem de fluxos por
classe da distribuicao do CSV original. Por isso, o notebook de rotulagem
inclui uma etapa de conferencia (comparacao da distribuicao de classes obtida
aqui com a distribuicao do CSV original da CICIDS2017) -- pequenos desajustes
de horario sao esperados e devem ser reportados como limitacao do trabalho.
"""

import re
from datetime import datetime
from zoneinfo import ZoneInfo

import pandas as pd

# UNB / Fredericton (NB, Canada) fica no fuso "America/Moncton" (Atlantic
# Time). Em julho de 2017 o horario de verao estava em vigor (UTC-3). Os
# horarios de ataque publicados no site sao horario local do laboratorio.
TZ = ZoneInfo("America/Moncton")

# IP interno do firewall para onde o trafego do atacante externo (Kali /
# maquinas Win do DDoS) e traduzido via NAT antes de entrar na rede da vitima.
NAT_GATEWAY_IP = "172.16.0.1"

# IPs de infraestrutura interna (servidores) na faixa 192.168.10.x. Trafego
# de/para essas maquinas costuma ser trafego normal de servico (DNS, LDAP,
# web, e-mail) e NAO deve ser varrido para "Infiltration" pelo wildcard de
# vitima usado no portscan interno de quinta-feira (ver _is_internal_client
# e o comentario no BUG #2 abaixo).
INTERNAL_INFRA_IPS = {
    "192.168.10.3",   # DNS/LDAP -- aparece nos fluxos NFStream nas portas 53/389
    "192.168.10.50",  # servidor web -- vitima de FTP/SSH-Patator, DoS, Web Attack
    "192.168.10.51",  # servidor de e-mail -- vitima do Heartbleed
    NAT_GATEWAY_IP,   # gateway do firewall (NAT)
}


def _is_internal_client(ip: str) -> bool:
    """True se o IP for uma maquina cliente da rede interna 192.168.10.x,
    excluindo os servidores de infraestrutura conhecidos (DNS/LDAP, web,
    e-mail, gateway NAT)."""
    return ip.startswith("192.168.10.") and ip not in INTERNAL_INFRA_IPS


def _dt_ms(date_str: str, time_str: str) -> int:
    dt = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M").replace(tzinfo=TZ)
    return int(dt.timestamp() * 1000)


def _com_nat(*ips):
    """Adiciona o IP do gateway NAT (172.16.0.1) como candidato extra a
    atacante, alem do(s) IP(s) publico(s) originais."""
    return list(ips) + [NAT_GATEWAY_IP]


# Cada entrada representa uma janela de ataque: data, hora de inicio, hora de
# fim, IP(s) do atacante (publico + NAT), IP(s) da vitima (publico e/ou local
# -- o mesmo host aparece com IPs diferentes dependendo de onde o PCAP foi
# capturado) e o rotulo a atribuir.
_RAW_WINDOWS = [
    # Terca-feira, 04/07/2017 -- Brute Force
    dict(date="2017-07-04", start="09:20", end="10:20",
         attacker=_com_nat("205.174.165.73"), victim=["205.174.165.68", "192.168.10.50"],
         label="FTP-Patator"),
    dict(date="2017-07-04", start="14:00", end="15:00",
         attacker=_com_nat("205.174.165.73"), victim=["205.174.165.68", "192.168.10.50"],
         label="SSH-Patator"),

    # Quarta-feira, 05/07/2017 -- DoS / DDoS / Heartbleed
    dict(date="2017-07-05", start="09:47", end="10:10",
         attacker=_com_nat("205.174.165.73"), victim=["205.174.165.68", "192.168.10.50"],
         label="DoS slowloris"),
    dict(date="2017-07-05", start="10:14", end="10:35",
         attacker=_com_nat("205.174.165.73"), victim=["205.174.165.68", "192.168.10.50"],
         label="DoS Slowhttptest"),
    dict(date="2017-07-05", start="10:43", end="11:00",
         attacker=_com_nat("205.174.165.73"), victim=["205.174.165.68", "192.168.10.50"],
         label="DoS Hulk"),
    dict(date="2017-07-05", start="11:10", end="11:23",
         attacker=_com_nat("205.174.165.73"), victim=["205.174.165.68", "192.168.10.50"],
         label="DoS GoldenEye"),
    dict(date="2017-07-05", start="15:12", end="15:32",
         attacker=_com_nat("205.174.165.73"), victim=["205.174.165.66", "192.168.10.51"],
         label="Heartbleed"),

    # Quinta-feira, 06/07/2017 -- Web Attack / Infiltration
    dict(date="2017-07-06", start="09:20", end="10:00",
         attacker=_com_nat("205.174.165.73"), victim=["205.174.165.68", "192.168.10.50"],
         label="Web Attack - Brute Force"),
    dict(date="2017-07-06", start="10:15", end="10:35",
         attacker=_com_nat("205.174.165.73"), victim=["205.174.165.68", "192.168.10.50"],
         label="Web Attack - XSS"),
    dict(date="2017-07-06", start="10:40", end="10:42",
         attacker=_com_nat("205.174.165.73"), victim=["205.174.165.68", "192.168.10.50"],
         label="Web Attack - Sql Injection"),
    dict(date="2017-07-06", start="14:19", end="14:35",
         attacker=_com_nat("205.174.165.73"), victim=["192.168.10.8"],
         label="Infiltration"),
    dict(date="2017-07-06", start="14:53", end="15:00",
         attacker=_com_nat("205.174.165.73"), victim=["192.168.10.25"],
         label="Infiltration"),
    dict(date="2017-07-06", start="15:04", end="15:45",
         attacker=_com_nat("205.174.165.73"), victim=["192.168.10.8"],
         label="Infiltration"),
    # segunda etapa da infiltracao de quinta: a propria Vista (ja infectada)
    # faz portscan interno contra os outros clientes -- sem NAT, e trafego
    # interno-interno.
    #
    # BUG #2 (corrigido): a vitima aqui era "*" (qualquer IP do universo).
    # Como o casamento em label_flow() e bidirecional (src OU dst no papel
    # de atacante), isso rotulava como Infiltration QUALQUER fluxo em que
    # 192.168.10.8 aparecesse -- inclusive trafego 100% normal desse host
    # com servidores de infraestrutura (DNS, LDAP, web, e-mail) durante os
    # 41 minutos da janela. Resultado: 67.849 fluxos rotulados como
    # Infiltration, contra 36 no CSV original da CICIDS2017 (~1900x).
    # Fix: "*_local" restringe a vitima a maquinas clientes da rede interna
    # 192.168.10.x, excluindo os servidores conhecidos (INTERNAL_INFRA_IPS).
    # Isso ainda e uma aproximacao (nao ha como distinguir portscan de
    # trafego normal cliente-cliente usando so IP+tempo), mas elimina a
    # maior fonte de falso positivo. Documentar como limitacao no relatorio.
    dict(date="2017-07-06", start="15:04", end="15:45",
         attacker=["192.168.10.8"], victim=["*_local"],
         label="Infiltration"),

    # Sexta-feira, 07/07/2017 -- Bot / PortScan / DDoS
    dict(date="2017-07-07", start="10:02", end="11:02",
         attacker=_com_nat("205.174.165.73"),
         victim=["192.168.10.15", "192.168.10.9", "192.168.10.14",
                 "192.168.10.5", "192.168.10.8"],
         label="Bot"),
    dict(date="2017-07-07", start="13:55", end="15:29",
         attacker=_com_nat("205.174.165.73"), victim=["205.174.165.68", "192.168.10.50"],
         label="PortScan"),
    dict(date="2017-07-07", start="15:56", end="16:16",
         attacker=_com_nat("205.174.165.69", "205.174.165.70", "205.174.165.71"),
         victim=["205.174.165.68", "192.168.10.50"],
         label="DDoS"),
]

ATTACK_WINDOWS = [
    {
        "start_ms": _dt_ms(w["date"], w["start"]),
        "end_ms": _dt_ms(w["date"], w["end"]),
        "attacker": set(w["attacker"]),
        "victim": set(w["victim"]),
        "label": w["label"],
    }
    for w in _RAW_WINDOWS
]


def _victim_matches(ip: str, window: dict) -> bool:
    """Verifica se `ip` pode ser considerado vitima da janela `window`.

    - victim == {'*'}       -> casa com QUALQUER IP (wildcard total; nao usado
                                atualmente em nenhuma janela, mantido por
                                flexibilidade, mas evite -- ver BUG #2 no
                                historico das janelas de Infiltration).
    - victim == {'*_local'} -> casa apenas com maquinas clientes da rede
                                interna 192.168.10.x, excluindo servidores de
                                infraestrutura conhecidos (INTERNAL_INFRA_IPS).
    - caso contrario        -> casa apenas com os IPs explicitos da janela.
    """
    if window["victim"] == {"*"}:
        return True
    if window["victim"] == {"*_local"}:
        return _is_internal_client(ip)
    return ip in window["victim"]


def label_flow(src_ip: str, dst_ip: str, first_seen_ms: int) -> str:
    """Rotula um unico fluxo com base em IP de origem/destino e no timestamp
    de inicio do fluxo. Retorna 'BENIGN' se nenhuma janela de ataque
    corresponder."""
    for w in ATTACK_WINDOWS:
        if not (w["start_ms"] <= first_seen_ms <= w["end_ms"]):
            continue
        pair_ok = (
            (src_ip in w["attacker"] and _victim_matches(dst_ip, w))
            or (dst_ip in w["attacker"] and _victim_matches(src_ip, w))
        )
        if pair_ok:
            return w["label"]
    return "BENIGN"


def label_dataframe(df, src_col="src_ip", dst_col="dst_ip",
                     time_col="bidirectional_first_seen_ms"):
    """Aplica label_flow a todas as linhas de um DataFrame gerado pelo
    NFStream e devolve uma copia com a coluna 'Label' adicionada."""
    df = df.copy()
    df["Label"] = [
        label_flow(s, d, t)
        for s, d, t in zip(df[src_col], df[dst_col], df[time_col])
    ]
    return df


# Encodings a tentar, em ordem, ao ler os CSVs originais da CICIDS2017.
# BUG #1 (corrigido): o notebook original usava encoding="latin1" direto,
# mas latin1 SEMPRE decodifica com sucesso (nunca lanca erro, mapeia byte a
# byte 1-para-1), entao nunca acusava problema -- so produzia texto
# corrompido em silencio quando o arquivo real era UTF-8 (o caractere
# en-dash "-" dos rotulos "Web Attack - XSS" etc. virava "ï¿½"). Por isso
# essa funcao tenta UTF-8 primeiro (que falha alto e claro se nao for o
# encoding certo) e so cai para os outros como fallback.
_ENCODINGS_CANDIDATOS = ["utf-8", "cp1252", "latin1"]


def ler_csv_original_cicids2017(caminhos, **kwargs):
    """Le e concatena os CSVs originais da CICIDS2017 (formato CICFlowMeter),
    tentando descobrir o encoding correto automaticamente em vez de assumir
    latin1 (ver BUG #1 no historico deste arquivo). Tambem ja remove os
    espacos em branco dos nomes de coluna (ex. ' Label' -> 'Label').

    Parametros
    ----------
    caminhos : list[str]
        Caminhos dos CSVs a carregar e concatenar (ex. saida de glob.glob).
    **kwargs : repassados para pandas.read_csv (exceto 'encoding').

    Retorna
    -------
    pandas.DataFrame
    """
    dfs = []
    for caminho in caminhos:
        ultimo_erro = None
        for enc in _ENCODINGS_CANDIDATOS:
            try:
                d = pd.read_csv(caminho, encoding=enc, **kwargs)
                print(f"[ler_csv_original_cicids2017] {caminho}: lido com encoding='{enc}'")
                dfs.append(d)
                break
            except UnicodeDecodeError as e:
                ultimo_erro = e
                continue
        else:
            raise ultimo_erro

    df = pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()
    df.columns = [c.strip() for c in df.columns]
    return df


_RE_NAO_ALFANUM = re.compile(r"[^0-9a-zA-Z]+")


def normalizar_label(label: str) -> str:
    """Normaliza um rotulo de ataque para servir de CHAVE DE COMPARACAO entre
    a Base A (nossa) e a Base B (CSV original da CICIDS2017).

    Contexto: alguns CSVs originais da CICIDS2017 ja chegam com o caractere
    de travessao dos rotulos ("Web Attack - XSS" etc.) substituido pelo
    U+FFFD REPLACEMENT CHARACTER, gravado como UTF-8 valido dentro do
    proprio arquivo -- ou seja, a informacao original ja foi perdida antes
    do CSV chegar ate nos, em algum ponto anterior da cadeia de distribuicao
    do dataset. NENHUM encoding de leitura recupera isso (ja testamos
    utf-8/cp1252/latin1 -- o arquivo le sem erro e o caractere continua
    sendo o replacement character).

    Por isso, em vez de tentar adivinhar o caractere original, normalizamos
    os dois lados: removemos tudo que nao for letra/numero e colocamos em
    minusculas. "Web Attack - XSS" e "Web Attack \ufffd XSS" viram ambos
    "webattackxss" e passam a bater na comparacao. Use esta funcao so para
    JUNTAR/COMPARAR contagens por classe -- mantenha a coluna original
    ("Label") para qualquer output final, ja que ela ainda e a mais legivel.
    """
    return _RE_NAO_ALFANUM.sub("", str(label)).lower()
