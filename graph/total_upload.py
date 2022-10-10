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

ax.bar(['1MB', '10MB', '100MB'], [1955, 9841, 91631])
ax.set(xlabel='store name', ylabel='profit')
ax.set_ylim(0, 100000)

plt.xlabel('content file size')
plt.ylabel('time(ms)')

plt.text(0,2055,1955, ha="center")
plt.text(1,9941,9841, ha="center")
plt.text(2,91731,91631, ha="center")

plt.savefig("total-upload.pdf")
plt.show()



