import numpy as np
import matplotlib.pyplot as plt
import csv
import pandas as pd

OUTPUT_FILE = './result2.csv'

with open(OUTPUT_FILE, 'r') as f:
    reader = csv.reader(f)
    l = [row for row in reader]

print(l)
data = [[482,486,83,53], [549,2319,660,514], [461,21021,6432,5128]]
print("data", data)
print("column", ['FindNodes', 'DownloadShards', 'VerifyMerkleProof', 'Decode'])
print("index", l[0])

dataset = pd.DataFrame(
     [[482,549,461], [486,2319,21021], [83,660,6432], [53,514,5128]], columns=['1MB', '10MB', '100MB'], index=['FindNodes', 'DownloadShards', 'VerifyMerkleProof', 'Decode'])

# print(dataset)

plt.rcParams["font.size"] = 24
fig, ax = plt.subplots(figsize=(10, 8))
for i in range(len(dataset)):
    ax.bar(dataset.columns, dataset.iloc[i], bottom=dataset.iloc[:i].sum())
ax.set(xlabel='store name', ylabel='profit')
ax.legend(dataset.index)
plt.xlabel('content file size')
plt.ylabel('time(ms)')

plt.text(0,1209,1109, ha="center")
plt.text(1,4142,4042, ha="center")
plt.text(2,33132,33032, ha="center")

plt.title('Total Time to Get A Content')

plt.savefig("total-download.pdf")
plt.show()
