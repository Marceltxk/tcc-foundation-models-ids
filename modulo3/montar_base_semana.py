"""
montar_base_semana.py -- rotula os 4 CSVs diarios do NFStream (terca a sexta)
com rotulagem_cicids2017.label_dataframe e junta tudo numa unica base.

Uso (a partir de ~/TCC_FoundationModels_IDS):
    python3 modulo3/montar_base_semana.py
    python3 modulo3/montar_base_semana.py --saida modulo3/base_semana_rotulada.csv

Entrada : modulo2/captura_nfstream_{tuesday,wednesday,thursday,friday}.csv
Saida   : CSV com so as colunas usadas nos modelos + Label + dia.
          IPs e timestamps sao usados para rotular e depois DESCARTADOS
          (o rotulo foi criado a partir deles, entao nao podem ser features).
"""
import argparse
import sys
from pathlib import Path

import pandas as pd

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "modulo2"))
sys.path.insert(0, str(RAIZ / "modulo3"))

from rotulagem_cicids2017 import label_dataframe  # noqa: E402
from pipeline_ids import BASE_FEATURES  # noqa: E402

DIAS = {"terca": "tuesday", "quarta": "wednesday", "quinta": "thursday", "sexta": "friday"}
COLS_ROTULAR = ["src_ip", "dst_ip", "bidirectional_first_seen_ms"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pasta", default=str(RAIZ / "modulo2"))
    ap.add_argument("--saida", default=str(RAIZ / "modulo3" / "base_semana_rotulada.csv"))
    a = ap.parse_args()

    partes = []
    for dia, nome in DIAS.items():
        csv = Path(a.pasta) / f"captura_nfstream_{nome}.csv"
        if not csv.exists():
            raise SystemExit(f"Nao encontrei {csv}")
        d = pd.read_csv(csv, usecols=COLS_ROTULAR + BASE_FEATURES, low_memory=False)
        d = label_dataframe(d)
        d = d.drop(columns=COLS_ROTULAR)
        d["dia"] = dia
        partes.append(d)
        print(f"[ok] {dia}: {len(d):,} fluxos")
        print(d["Label"].value_counts().to_string(), "\n")

    base = pd.concat(partes, ignore_index=True)
    base.to_csv(a.saida, index=False)
    print(f"Base salva em {a.saida}: {base.shape}")
    print(base["Label"].value_counts().to_string())


if __name__ == "__main__":
    main()
