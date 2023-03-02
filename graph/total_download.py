import numpy as np
import matplotlib.pyplot as plt
import csv
import pandas as pd

OUTPUT_FILE = './result2.csv'

with open(OUTPUT_FILE, 'r') as f:
    reader = csv.reader(f)
    l = [row for row in reader]

print(l)

plt.rcParams["font.size"] = 32
fig, ax = plt.subplots(figsize=(10, 8))

result_1MB = 521
result_10MB = 1031
result_100MB = 4893

# 数値を出す場所と棒との間隔
margin = 20

ax.bar(['1MB', '10MB', '100MB'], [result_1MB, result_10MB, result_100MB])
ax.set(xlabel='store name', ylabel='profit')
ax.set_ylim(0, 5200)

plt.xlabel('content file size')
plt.ylabel('time(ms)')

plt.text(0,result_1MB + margin,result_1MB, ha="center")
plt.text(1,result_10MB + margin,result_10MB, ha="center")
plt.text(2,result_100MB + margin,result_100MB, ha="center")

plt.savefig("total-download.pdf")
plt.show()