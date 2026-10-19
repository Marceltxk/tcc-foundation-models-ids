# Resumo dos resultados (conjunto de TESTE)

## binario

| modelo             |    AUC |   AUC_PR |     F1 |   Precisao |   Recall |   tempo_treino_s |
|:-------------------|-------:|---------:|-------:|-----------:|---------:|-----------------:|
| LogisticRegression | 0.9823 |   0.9355 | 0.8782 |     0.8102 |   0.9588 |          12.5329 |
| DecisionTree       | 0.9978 |   0.9904 | 0.9764 |     0.955  |   0.9988 |           5.1584 |
| RandomForest       | 0.9974 |   0.9849 | 0.9838 |     0.969  |   0.9989 |          37.8495 |
| LightGBM           | 0.999  |   0.9962 | 0.9812 |     0.9641 |   0.9989 |           6.1264 |
| MLP                | 0.9987 |   0.9948 | 0.9792 |     0.9656 |   0.9933 |          72.1464 |

## multiclasse

| modelo             |    AUC |   AUC_PR |     F1 |   Precisao |   Recall |   tempo_treino_s |
|:-------------------|-------:|---------:|-------:|-----------:|---------:|-----------------:|
| LogisticRegression | 0.994  |   0.6376 | 0.6089 |     0.5293 |   0.9032 |          96.8568 |
| DecisionTree       | 0.9868 |   0.8766 | 0.8929 |     0.8858 |   0.9404 |           7.7597 |
| RandomForest       | 0.9791 |   0.8911 | 0.911  |     0.8935 |   0.9332 |          28.4869 |
| LightGBM           | 0.9995 |   0.8791 | 0.8868 |     0.8618 |   0.9433 |          54.1256 |
| MLP                | 0.9992 |   0.8653 | 0.8429 |     0.9591 |   0.8499 |          69.7041 |

## por_ataque_RandomForest

| ataque                   | modelo       |   n_ataque |    AUC |   AUC_PR |     F1 |   Precisao |   Recall |
|:-------------------------|:-------------|-----------:|-------:|---------:|-------:|-----------:|---------:|
| PortScan                 | RandomForest |      16014 | 0.9995 |   0.9941 | 0.9973 |     0.9947 |   0.9999 |
| DDoS                     | RandomForest |       6298 | 0.9999 |   0.9975 | 0.9967 |     0.9934 |   1      |
| Infiltration             | RandomForest |       5513 | 0.9965 |   0.8911 | 0.928  |     0.8665 |   0.9987 |
| DoS Hulk                 | RandomForest |       1429 | 1      |   1      | 0.9993 |     1      |   0.9986 |
| DoS GoldenEye            | RandomForest |        766 | 1      |   0.9986 | 0.9967 |     0.9948 |   0.9987 |
| DoS slowloris            | RandomForest |        448 | 1      |   0.9973 | 0.9933 |     0.9889 |   0.9978 |
| DoS Slowhttptest         | RandomForest |        437 | 1      |   0.9905 | 0.9954 |     0.9909 |   1      |
| FTP-Patator              | RandomForest |        395 | 1      |   0.9949 | 0.9962 |     0.9925 |   1      |
| SSH-Patator              | RandomForest |        246 | 0.9998 |   0.8851 | 0.9245 |     0.8627 |   0.9959 |
| Web Attack - Brute Force | RandomForest |        135 | 0.9888 |   0.9583 | 0.9314 |     0.9085 |   0.9556 |
| Bot                      | RandomForest |         73 | 1      |   1      | 1      |     1      |   1      |
| Web Attack - XSS         | RandomForest |         66 | 0.9922 |   0.9074 | 0.8657 |     0.8529 |   0.8788 |
