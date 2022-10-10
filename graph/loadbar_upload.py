import numpy as np
import matplotlib.pyplot as plt
import csv
import pandas as pd

OUTPUT_FILE = './result2.csv'

with open(OUTPUT_FILE, 'r') as f:
    reader = csv.reader(f)
    l = [row for row in reader]

dataset = pd.DataFrame(
     [[116,867,8693], [156,1278,12735], [975,924,1249], [708,6772,68954]], columns=['1MB', '10MB', '100MB'], index=['Encode', 'BuildMerkleTree', 'FindNodes', 'UploadShards'])

# print(dataset)

plt.rcParams["font.size"] = 24

fig, ax = plt.subplots(figsize=(10, 8))
for i in range(len(dataset)):
    ax.bar(dataset.columns, dataset.iloc[i], bottom=dataset.iloc[:i].sum())
ax.set(xlabel='store name', ylabel='profit')

ax.legend(dataset.index)
plt.xlabel('content file size')
plt.ylabel('time(ms)')

plt.text(0,2055,1955, ha="center")
plt.text(1,9941,9841, ha="center")
plt.text(2,91731,91631, ha="center")
plt.title('Total Time to Upload A Content')

plt.savefig("total-upload.pdf")
plt.show()
