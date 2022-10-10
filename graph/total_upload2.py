import numpy as np
import matplotlib.pyplot as plt
import csv
import pandas as pd

OUTPUT_FILE = './result2.csv'

with open(OUTPUT_FILE, 'r') as f:
    reader = csv.reader(f)
    l = [row for row in reader]

dataset = pd.DataFrame(
     [[708,6772,68954], [1247,3069,22677]], columns=['1MB', '10MB', '100MB'], index=['Upload', 'Others'])

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

plt.text(0,2055,1955, ha="center")
plt.text(1,9941,9841, ha="center")
plt.text(2,91731,91631, ha="center")

plt.savefig("total-upload.pdf")
plt.show()
