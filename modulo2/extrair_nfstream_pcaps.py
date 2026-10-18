"""
extrair_nfstream_pcaps.py

Roda o NFStream nos PCAPs originais da CICIDS2017 (um por dia) e salva um CSV
por dia, no padrao de nome que as notebooks do Modulo 2 esperam:

    captura_nfstream_tuesday.csv
    captura_nfstream_wednesday.csv
    captura_nfstream_thursday.csv
    captura_nfstream_friday.csv
    (captura_nfstream_monday.csv so se pedir a segunda-feira explicitamente)

Os PCAPs sao grandes (9 a 13 GB cada), entao a extracao demora. O script:
  - salva primeiro num arquivo temporario (.partial) e so renomeia no final,
    para um CSV incompleto nunca ser confundido com um CSV pronto;
  - pula dias cujo CSV final ja existe (use --forcar para refazer);
  - procura os PCAPs em dados/pcaps, ../dados/pcaps e dados, sem diferenciar
    maiusculas de minusculas (ex.: "Wednesday-workingHours.pcap").

Uso (a partir da pasta modulo2/):
    python extrair_nfstream_pcaps.py                      # terca a sexta
    python extrair_nfstream_pcaps.py --dias quinta        # so um dia
    python extrair_nfstream_pcaps.py --dias segunda terca # varios dias
    python extrair_nfstream_pcaps.py --forcar             # refaz tudo
"""

import argparse
import os
import sys
import time

from nfstream import NFStreamer

# nome em portugues (argumento) -> (prefixo do PCAP, sufixo do CSV de saida)
DIAS = {
    "segunda": ("monday", "monday"),
    "terca": ("tuesday", "tuesday"),
    "quarta": ("wednesday", "wednesday"),
    "quinta": ("thursday", "thursday"),
    "sexta": ("friday", "friday"),
}
DIAS_PADRAO = ["terca", "quarta", "quinta", "sexta"]
PASTAS_BUSCA = ["dados/pcaps", "../dados/pcaps", "dados"]


def achar_pcap(prefixo, pastas=PASTAS_BUSCA):
    """Procura o .pcap do dia nas pastas candidatas, ignorando maiusculas."""
    for pasta in pastas:
        if not os.path.isdir(pasta):
            continue
        for nome in sorted(os.listdir(pasta)):
            n = nome.lower()
            if n.startswith(prefixo) and n.endswith(".pcap"):
                return os.path.join(pasta, nome)
    return None


def extrair_dia(pcap, saida, forcar=False):
    if os.path.exists(saida) and not forcar:
        print(f"  [pulando] {saida} ja existe (use --forcar para refazer)")
        return None

    parcial = saida + ".partial"
    inicio = time.time()
    # Parametros padrao do NFStream (idle_timeout=120s, active_timeout=1800s),
    # os mesmos usados na extracao de quinta-feira.
    streamer = NFStreamer(source=pcap)
    n_fluxos = streamer.to_csv(path=parcial, flows_per_file=0)
    os.replace(parcial, saida)
    minutos = (time.time() - inicio) / 60
    print(f"  [ok] {n_fluxos} fluxos salvos em {saida} ({minutos:.1f} min)")
    return n_fluxos


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dias", nargs="+", choices=list(DIAS), default=DIAS_PADRAO,
                    help="dias a processar (padrao: terca quarta quinta sexta)")
    ap.add_argument("--forcar", action="store_true", help="refaz mesmo se o CSV ja existir")
    ap.add_argument("--saida", default=".", help="pasta onde salvar os CSVs (padrao: pasta atual)")
    args = ap.parse_args()

    faltando = []
    for dia in args.dias:
        prefixo, sufixo = DIAS[dia]
        pcap = achar_pcap(prefixo)
        print(f"\n=== {dia} ===")
        if pcap is None:
            print(f"  [ERRO] PCAP de {dia} nao encontrado em: {', '.join(PASTAS_BUSCA)}")
            faltando.append(dia)
            continue
        print(f"  PCAP: {pcap} ({os.path.getsize(pcap) / 1e9:.1f} GB)")
        saida = os.path.join(args.saida, f"captura_nfstream_{sufixo}.csv")
        extrair_dia(pcap, saida, forcar=args.forcar)

    if faltando:
        print("\nDias sem PCAP encontrado:", ", ".join(faltando))
        sys.exit(1)
    print("\nExtracao concluida.")


if __name__ == "__main__":
    main()
