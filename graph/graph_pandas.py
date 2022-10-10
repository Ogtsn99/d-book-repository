import numpy as np
import matplotlib.pyplot as plt
import csv
import pandas as pd

l = [['', 'FindNodes', 'DownloadShards', 'VerifyMerkleProof', 'Decode'], ['1MB', 482, 486, 83, 53], ['10MB', 549, 2319, 660, 514], ['100MB', 461, 21021, 6432, 5128]]

df = pd.read_csv('result.csv')

print(df)

df.plot.bar('_key', 'FindNodes')

fig, axes = plt.subplots(nrows=2, ncols=2, figsize=(8, 8))

df.plot('_key', 'FindNodes', kind="bar", ax=axes[0, 0], legend=False, title="time to find 20 nodes")
axes[0, 0].text(0,2055,1955, ha="center")
axes[0, 0].text(1,9941,9841, ha="center")
axes[0, 0].text(2,91731,91631, ha="center")
df.plot('_key', 'DownloadShards', kind="bar", ax=axes[0, 1], legend=False, title="time to download 20 shards")
df.plot('_key', 'VerifyMerkleProof', kind="bar", ax=axes[1, 0], legend=False, title="time to verify Merkle proofs")
df.plot('_key', 'Decode', kind="bar", ax=axes[1, 1], legend=False, title="time to decode")

fig.savefig('test.png')
