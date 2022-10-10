import numpy as np
import matplotlib.pyplot as plt
import csv
import pandas as pd

OUTPUT_FILE = './result2.csv'

with open(OUTPUT_FILE, 'r') as f:
    reader = csv.reader(f)
    l = [row for row in reader]

dataset = pd.DataFrame(
     [[486,2319,21021], [618,1720,12021]], columns=['1MB', '10MB', '100MB'], index=['Download', 'Others'])

# print(dataset)

plt.rcParams["font.size"] = 24
fig, ax = plt.subplots(figsize=(10, 8))

colors = ["red", "grey"]

for i in range(len(dataset)):
    print(i)
    ax.bar(dataset.columns, dataset.iloc[i], bottom=dataset.iloc[:i].sum(), color=colors[i])
ax.set(xlabel='store name', ylabel='profit')
ax.legend(dataset.index)
plt.xlabel('the size of e-book data')
plt.ylabel('Elapsed time [ms]')

plt.text(0,1204,1104, ha="center")
plt.text(1,4142,4039, ha="center")
plt.text(2,33132,33042, ha="center")

plt.savefig("total-download.pdf")
plt.show()
