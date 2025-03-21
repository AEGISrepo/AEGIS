import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FuncFormatter, MultipleLocator


df = pd.read_excel("metric_results.xlsx", sheet_name=0)

df = df[["Item", "Type", "Percentage"]].copy()


item_mapping = {
    "httpd": "Apache HTTP Server",
    "iperf3": "iPerf3",
    "memcached": "Memcached",
    "nginx": "Nginx",
    "postgres": "PostgreSQL",
    "redis": "Redis",
}
df["Item"] = df["Item"].map(item_mapping)


df["Percentage"] = df["Percentage"].abs()


df.sort_values(by=["Item", "Type"], inplace=True)


df["Type"] = df["Type"].astype(str) + " vulns"


sns.set(style="whitegrid", context="paper", font_scale=2.0)


plt.figure(figsize=(9, 6))  # figsize=(10,6)  10

sns.lineplot(
    data=df,
    x="Type",
    y="Percentage",
    hue="Item",
    style="Item",
    markers=True,
    dashes=True,
    linewidth=3.5,
    markersize=14
)

# ，
plt.xlabel("")
plt.ylabel("Overhead", fontsize=22)


upbound = 26
plt.ylim(0, upbound)


ax = plt.gca()
ax.yaxis.set_major_locator(MultipleLocator(5))
ax.yaxis.set_major_formatter(FuncFormatter(
    lambda x, pos: f"{int(x)}%" if x != 0 else "0"))


plt.legend(loc="best", fontsize=22, title_fontsize=20)

plt.tight_layout()
plt.savefig("figures.pdf", format="pdf")
plt.show()
