import numpy as np
import matplotlib.pyplot as plt

Category = ["1MB", "10MB", "100MB"] # カテゴリ名
Value_1 = [482,546,461]           # 系列 1 のデータ
Value_2 = [83,660,6432]            # 系列 2 のデータ
Value_3 = [53,514,5128]            # 系列 3 のデータ

x_1 = [0, 1.6, 3.2]            # 系列 1 をプロットするx座標
x_2 = [0.4, 2.0, 3.6]  # 系列 2 をプロットするx座標
x_3 = [0.8, 2.4, 4.0]  # 系列 3 をプロットするx座標

plt.bar(x_1, Value_1, color='b', width=0.3, label='Find 20 Peers', alpha=0.5)
plt.bar(x_2, Value_2, color='g', width=0.3, label='Check Merkle Proofs', alpha=0.5)
plt.bar(x_3, Value_3, color='r', width=0.3, label='Decode', alpha=0.5)

plt.legend() # ラベル表示
plt.xticks(x_2 , Category) # X軸にカテゴリ名表示

plt.xlabel('the size of e-book data')
plt.ylabel('Elapsed time [ms]')

plt.text(0,482+60,482, ha="center")
plt.text(0.4,83+60,83, ha="center")
plt.text(0.8,53+60,53, ha="center")

plt.text(1.6,546+60,546, ha="center")
plt.text(2.0,660+60,660, ha="center")
plt.text(2.4,514+60,514, ha="center")

plt.text(3.2,461+60,461, ha="center")
plt.text(3.6,6432+60,6432, ha="center")
plt.text(4.0,5128+60,5128, ha="center")

plt.savefig("download_all.pdf")
plt.show()


