from pathlib import Path
import pandas as pd

path = Path('evaluation/raw/UNSW_NB15_training-set.csv')
df = pd.read_csv(path)
ids = pd.to_numeric(df['id'], errors='coerce').fillna(-1).astype(int)
for mask_name, mask in [('train', ids.mod(10) != 0), ('holdout', ids.mod(10) == 0)]:
    print(mask_name, len(df[mask]), df.loc[mask, 'label'].value_counts().to_dict())
