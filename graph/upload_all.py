import numpy as np
import matplotlib.pyplot as plt
import csv
import pandas as pd

plt.rcParams["font.size"] = 11
#figure()でグラフを表示する領域をつくり，figというオブジェクトにする．
fig = plt.figure()

df = pd.read_csv('result.csv')

#add_subplot()でグラフを描画する領域を追加する．引数は行，列，場所
ax1 = fig.add_subplot(2, 2, 1)
ax2 = fig.add_subplot(2, 2, 2)
ax3 = fig.add_subplot(2, 2, 3)
ax4 = fig.add_subplot(2, 2, 4)

t = np.linspace(-10, 10, 1000)
y1 = np.sin(t)
y2 = np.cos(t) 
y3 = np.abs(np.sin(t))
y4 = np.sin(t)**2

c1,c2,c3,c4 = "blue","green","red","black"      # 各プロットの色
l1,l2,l3,l4 = "sin","cos","abs(sin)","sin**2"   # 各ラベル

ax1.bar(["1MB", "10MB", "100MB"],[116,867,8693], color="#1f76b5")
ax1.set(ylabel='time(ms)')
ax1.set_title('Time to Encode')
ax1.text(0,116,116, ha="center")
ax1.text(1,867,867, ha="center")
ax1.text(2,8000,8693, ha="center")


ax2.bar(["1MB", "10MB", "100MB"],[156,1278,12735], color="#ff7e0f")
ax2.set(ylabel='time(ms)')
ax2.set_title('Time to Build Merkle Tree')
ax2.text(0,156,156, ha="center")
ax2.text(1,1278,1278, ha="center")
ax2.text(2,11635,12735, ha="center")


ax3.bar(["1MB", "10MB", "100MB"],[975,924,1249], color="#2da12c")
ax3.set(ylabel='time(ms)')
ax3.set_title('Time to Find 40 Nodes')
ax3.text(0,975,975, ha="center")
ax3.text(1,924,924, ha="center")
ax3.text(2,1149,1249, ha="center")

ax4.bar(["1MB", "10MB", "100MB"],[708,6772,68954], color="#d72628")
ax4.set(ylabel='time(ms)')
ax4.set_title('Time to Upload Shards')
ax4.text(0,708,708, ha="center")
ax4.text(1,6772,6772, ha="center")
ax4.text(2,62954,68954, ha="center")

fig.tight_layout()              #レイアウトの設定
plt.savefig("upload_all.pdf")
plt.show()