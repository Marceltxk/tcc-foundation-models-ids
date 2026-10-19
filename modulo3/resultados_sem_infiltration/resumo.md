# Resumo dos resultados (conjunto de TESTE)

## binario

| modelo             |    AUC |   AUC_PR |     F1 |   Precisao |   Recall |   tempo_treino_s |
|:-------------------|-------:|---------:|-------:|-----------:|---------:|-----------------:|
| LogisticRegression | 0.9886 |   0.9355 | 0.8862 |     0.8221 |   0.9612 |          15.5831 |
| DecisionTree       | 0.9986 |   0.9934 | 0.9867 |     0.9751 |   0.9986 |           3.7286 |
| RandomForest       | 0.9993 |   0.9948 | 0.996  |     0.9931 |   0.999  |          31.2992 |
| LightGBM           | 0.9997 |   0.9987 | 0.9933 |     0.9882 |   0.9985 |           4.4466 |
| MLP                | 0.9996 |   0.9981 | 0.9913 |     0.9903 |   0.9924 |          54.8007 |

## multiclasse

| modelo             |    AUC |   AUC_PR |     F1 |   Precisao |   Recall |   tempo_treino_s |
|:-------------------|-------:|---------:|-------:|-----------:|---------:|-----------------:|
| LogisticRegression | 0.9941 |   0.592  | 0.5705 |     0.4884 |   0.8996 |          81.5904 |
| DecisionTree       | 0.9841 |   0.8682 | 0.8866 |     0.8711 |   0.9357 |           5.5119 |
| RandomForest       | 0.9745 |   0.8902 | 0.9092 |     0.892  |   0.9304 |          21.9118 |
| LightGBM           | 0.5683 |   0.1533 | 0.1623 |     0.2273 |   0.1844 |          43.0697 |
| MLP                | 0.9995 |   0.8587 | 0.8313 |     0.9633 |   0.8371 |          46.7565 |

## por_ataque_RandomForest

| ataque                   | modelo       |   n_ataque |    AUC |   AUC_PR |     F1 |   Precisao |   Recall |
|:-------------------------|:-------------|-----------:|-------:|---------:|-------:|-----------:|---------:|
| PortScan                 | RandomForest |      16013 | 0.9995 |   0.9941 | 0.9972 |     0.9947 |   0.9998 |
| DDoS                     | RandomForest |       6298 | 0.9999 |   0.9977 | 0.9966 |     0.9932 |   1      |
| DoS Hulk                 | RandomForest |       1428 | 1      |   1      | 0.9982 |     1      |   0.9965 |
| DoS GoldenEye            | RandomForest |        766 | 1      |   0.9973 | 0.9967 |     0.9948 |   0.9987 |
| DoS slowloris            | RandomForest |        448 | 1      |   0.9972 | 0.9933 |     0.9889 |   0.9978 |
| DoS Slowhttptest         | RandomForest |        437 | 1      |   0.9903 | 0.9932 |     0.9909 |   0.9954 |
| FTP-Patator              | RandomForest |        395 | 1      |   0.9949 | 0.9962 |     0.9925 |   1      |
| SSH-Patator              | RandomForest |        246 | 0.9999 |   0.8935 | 0.9266 |     0.8632 |   1      |
| Web Attack - Brute Force | RandomForest |        135 | 0.9925 |   0.9549 | 0.9091 |     0.8609 |   0.963  |
| Bot                      | RandomForest |         74 | 1      |   1      | 1      |     1      |   1      |
| Web Attack - XSS         | RandomForest |         66 | 0.9847 |   0.9205 | 0.8759 |     0.8451 |   0.9091 |
