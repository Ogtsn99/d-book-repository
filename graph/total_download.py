import numpy as np
import matplotlib.pyplot as plt
import csv
import pandas as pd

OUTPUT_FILE = './result2.csv'

with open(OUTPUT_FILE, 'r') as f:
    reader = csv.reader(f)
    l = [row for row in reader]

print(l)

plt.rcParams["font.size"] = 24
fig, ax = plt.subplots(figsize=(10, 8))

ax.bar(['1MB', '10MB', '100MB'], [1109, 4042, 33032])
ax.set(xlabel='store name', ylabel='profit')
ax.set_ylim(0, 100000)

plt.xlabel('content file size')
plt.ylabel('time(ms)')

plt.text(0,1209,1109, ha="center")
plt.text(1,4142,4042, ha="center")
plt.text(2,33132,33032, ha="center")

plt.savefig("total-download.pdf")
plt.show()