import pandas as pd


def calcular_cotas_balanceadas(contagem_classes, n_amostras):
    """
    Calcula quantas amostras pegar de cada classe, tentando balancear ao máximo.
    """
    classes = contagem_classes.index.tolist()
    n_classes = len(classes)

    base = n_amostras // n_classes
    resto = n_amostras % n_classes

    cotas = {}
    for i, classe in enumerate(classes):
        cotas[classe] = base + (1 if i < resto else 0)

    return cotas


def subamostrar_balanceado(
    arquivo_entrada: str,
    arquivo_saida: str = "dataset_subamostrado.csv",
    n_amostras: int = 1000,
    seed: int = 42,
    split: bool = False,
    proporcao_treino: float = 0.8
) -> None:
    df = pd.read_csv(arquivo_entrada)

    if df.empty:
        raise ValueError("O arquivo CSV está vazio.")

    if not (0 < proporcao_treino < 1):
        raise ValueError("A proporção de treino deve estar entre 0 e 1.")

    coluna_classe = df.columns[-1]
    contagem_classes = df[coluna_classe].value_counts()

    if len(contagem_classes) == 0:
        raise ValueError("Nenhuma classe encontrada no dataset.")

    if len(df) < n_amostras:
        raise ValueError(
            f"O dataset tem apenas {len(df)} linhas, menor que n_amostras={n_amostras}."
        )

    # Define a meta inicial por classe
    cotas = calcular_cotas_balanceadas(contagem_classes, n_amostras)

    amostras = []
    faltantes = 0

    # Primeiro passo: tenta coletar conforme a cota por classe
    for classe, cota in cotas.items():
        grupo = df[df[coluna_classe] == classe]

        if len(grupo) >= cota:
            amostra = grupo.sample(n=cota, random_state=seed)
            amostras.append(amostra)
        else:
            # pega tudo da classe se não houver exemplos suficientes
            amostras.append(grupo)
            faltantes += (cota - len(grupo))

    df_sub = pd.concat(amostras)

    # Segundo passo: completa com exemplos ainda não usados
    if faltantes > 0:
        restantes = df.drop(df_sub.index)

        if len(restantes) < faltantes:
            raise ValueError(
                "Não há exemplos suficientes para completar a subamostra desejada."
            )

        extra = restantes.sample(n=faltantes, random_state=seed)
        df_sub = pd.concat([df_sub, extra])

    # Embaralha o resultado final
    df_sub = df_sub.sample(frac=1, random_state=seed).reset_index(drop=True)

    # Sem split: salva apenas um arquivo
    if not split:
        df_sub.to_csv(arquivo_saida, index=False)

        print(f"Subamostragem salva em: {arquivo_saida}")
        print(f"Tamanho final: {len(df_sub)}")
        print("\nDistribuição das classes:")
        print(df_sub[coluna_classe].value_counts())
        return

    # Com split balanceado (estratificado por classe)
    partes_treino = []
    partes_teste = []

    for classe, grupo in df_sub.groupby(coluna_classe):
        grupo = grupo.sample(frac=1, random_state=seed).reset_index(drop=True)

        n_treino = int(len(grupo) * proporcao_treino)

        # garante pelo menos 1 no treino e 1 no teste quando possível
        if len(grupo) >= 2:
            n_treino = max(1, min(n_treino, len(grupo) - 1))

        treino = grupo.iloc[:n_treino]
        teste = grupo.iloc[n_treino:]

        partes_treino.append(treino)
        partes_teste.append(teste)

    df_treino = pd.concat(partes_treino).sample(frac=1, random_state=seed).reset_index(drop=True)
    df_teste = pd.concat(partes_teste).sample(frac=1, random_state=seed).reset_index(drop=True)

    # Define nomes dos arquivos de saída
    if arquivo_saida.lower().endswith(".csv"):
        base = arquivo_saida[:-4]
    else:
        base = arquivo_saida

    arquivo_treino = f"{base}_train.csv"
    arquivo_teste = f"{base}_test.csv"

    df_treino.to_csv(arquivo_treino, index=False)
    df_teste.to_csv(arquivo_teste, index=False)

    print(f"Subamostragem balanceada criada com split.")
    print(f"Treino salvo em: {arquivo_treino}")
    print(f"Teste salvo em: {arquivo_teste}")
    print(f"\nTamanho treino: {len(df_treino)}")
    print(f"Tamanho teste: {len(df_teste)}")

    print("\nDistribuição das classes no treino:")
    print(df_treino[coluna_classe].value_counts())

    print("\nDistribuição das classes no teste:")
    print(df_teste[coluna_classe].value_counts())


# Exemplo de uso
if __name__ == "__main__":
    subamostrar_balanceado(
        arquivo_entrada="C:\\Users\\Silvio\\Downloads\\ERENO-2.0-100K.csv",
        arquivo_saida="C:\\Users\\Silvio\\Downloads\\ERENO-2.0-1K.csv",
        n_amostras=1000,
        seed=42,
        split=True,             # ativa o split balanceado
        proporcao_treino=0.8    # 80% treino, 20% teste
    )