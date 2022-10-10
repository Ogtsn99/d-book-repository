import numpy as np
import matplotlib.pyplot as plt

Category = ["1MB", "10MB", "100MB"] # カテゴリ名
Value_1 = [975,924,1249]           # 系列 1 のデータ
Value_2 = [156,1278,12735]            # 系列 2 のデータ
Value_3 = [116,867,8693]             # 系列 3 のデータ

x_1 = [0, 1.6, 3.2]            # 系列 1 をプロットするx座標
x_2 = [0.4, 2.0, 3.6]  # 系列 2 をプロットするx座標
x_3 = [0.8, 2.4, 4.0]  # 系列 3 をプロットするx座標

plt.bar(x_1, Value_1, color='b', width=0.3, label='Find 40 Peers', alpha=0.5)
plt.bar(x_2, Value_2, color='g', width=0.3, label='Build Merkle Tree', alpha=0.5)
plt.bar(x_3, Value_3, color='r', width=0.3, label='Encode', alpha=0.5)

plt.legend() # ラベル表示
plt.xticks(x_2 , Category) # X軸にカテゴリ名表示

plt.xlabel('the size of e-book data')
plt.ylabel('Elapsed time [ms]')

plt.text(0,975+100,975, ha="center")
plt.text(0.4,156+100,156, ha="center")
plt.text(0.8,116+100,116, ha="center")

plt.text(1.6,924+100,924, ha="center")
plt.text(2.0,1278+100,1278, ha="center")
plt.text(2.4,867+100,867, ha="center")

plt.text(3.2,1249+100,1249, ha="center")
plt.text(3.6,12735+100,12735, ha="center")
plt.text(4.0,8693+100,8693, ha="center")

plt.savefig("upload_all.pdf")
plt.show()


