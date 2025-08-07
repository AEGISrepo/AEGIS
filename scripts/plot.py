import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FuncFormatter, MultipleLocator
import os

if len(os.sys.argv) != 2:
    exit(1)

df = pd.read_csv(os.sys.argv[1])

df = df[["Benchmark", "Type", "Overhead_Percentage"]].copy()

benchmark_mapping = {
    "Apache": "Apache HTTP Server",
    "iPerf": "iPerf3",
    "Memcached": "Memcached",
    "Nginx": "Nginx",
    "PostgreSQL": "PostgreSQL",
    "Redis": "Redis",
}
df["Benchmark"] = df["Benchmark"].map(benchmark_mapping)


df["Overhead_Percentage"] = (
    df["Overhead_Percentage"]
    .str.replace("%", "")
    .astype(float)
    .abs()
)


df.sort_values(by=["Benchmark", "Type"], inplace=True)


df["Type"] = df["Type"].astype(str)


sns.set(style="whitegrid", context="paper", font_scale=2.8)


plt.figure(figsize=(9, 6))

sns.lineplot(
    data=df,
    x="Type",
    y="Overhead_Percentage",
    hue="Benchmark",
    style="Benchmark",
    markers=True,
    dashes=True,
    linewidth=3.5,
    markersize=14,
    estimator="mean",
    errorbar=("ci", 95),
)


plt.xlabel("")
plt.ylabel("Overhead", fontsize=24)


upbound = 12
plt.ylim(0, upbound)


ax = plt.gca()
ax.yaxis.set_major_locator(MultipleLocator(2))
ax.yaxis.set_major_formatter(
    FuncFormatter(lambda x, pos: f"{int(x)}%" if x != 0 else "0")
)

plt.legend(loc="best", fontsize=23, title_fontsize=20)

plt.tight_layout()
plt.savefig("pdf.pdf", format="pdf")
plt.show()
