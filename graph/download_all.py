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

#     _key  FindNodes  DownloadShards  VerifyMerkleProof  Decode
# 0    1MB        482             486                 83      53
# 1   10MB        549            2319                660     514
# 2  100MB        461           21021               6432    5128

ax1.bar(["1MB", "10MB", "100MB"],[482, 549, 461], color="#1f76b5")
ax1.set(ylabel='time(ms)')
ax1.set_title('Time to Find 20 Nodes')
ax1.text(0,482,482, ha="center")
ax1.text(1,500,546, ha="center")
ax1.text(2,461,461, ha="center")


ax2.bar(["1MB", "10MB", "100MB"],[486, 2319, 21201], color="#ff7e0f")
ax2.set(ylabel='time(ms)')
ax2.set_title('Time to Download shards')
ax2.text(0,486,486, ha="center")
ax2.text(1,2319,2319, ha="center")
ax2.text(2,19221,21021, ha="center")


ax3.bar(["1MB", "10MB", "100MB"],[83, 660, 6432], color="#2da12c")
ax3.set(ylabel='time(ms)')
ax3.set_title('Time to Verify Merkle Proofs')
ax3.text(0,83,83, ha="center")
ax3.text(1,660,660, ha="center")
ax3.text(2,5832,6432, ha="center")

ax4.bar(["1MB", "10MB", "100MB"],[53, 514, 5128], color="#d72628")
ax4.set(ylabel='time(ms)')
ax4.set_title('Time to Decode')
ax4.text(0,53,53, ha="center")
ax4.text(1,514,514, ha="center")
ax4.text(2,4628,5128, ha="center")

fig.tight_layout()              #レイアウトの設定
plt.savefig("download_all.pdf")
plt.show()