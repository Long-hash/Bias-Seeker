# BiasSeeker AutoDL 复现实验说明

这个仓库用于在 AutoDL 上复现论文 **Bias in the Shadows: Explore Shortcuts in Encrypted Network Traffic Classification** 的实验流程。

整个流水线是“严格可恢复”的：

- 不会静默跳过任何数据集、模型、shortcut mitigation 策略或失败阶段。
- 如果自动下载数据集失败，或某个实验阶段失败，会生成失败报告，并等待你手动修复。
- 你修复后再次运行同一个命令，系统会从上次中断的位置继续执行。
- NetMamba 和 Decision Tree 两个模型都会保留，并生成两模型对比结果和单模型独立结果。
- 加密应用分类相关实验会生成单独的重点报告。

## AutoDL 环境准备

建议创建一台 H800 80GB GPU 的 AutoDL 实例，然后把本项目上传或 clone 到实例中。

基础依赖安装：

```bash
apt-get update
apt-get install -y tshark
python -m pip install -e .
```

如果安装 `tshark` 时询问是否允许非 root 用户抓包，任选即可。这里主要使用 `tshark` 做离线 pcap 解析，不需要在线抓包权限。

## NetMamba 官方代码接入

NetMamba 官方实现仓库是 `wangtz19/NetMamba`。

运行下面的脚本可以自动拉取官方代码并安装依赖：

```bash
bash scripts/setup_netmamba_official.sh
```

这个脚本会：

- clone `https://github.com/wangtz19/NetMamba.git`
- 安装官方仓库自带的 Mamba 1.1.1 扩展
- 安装官方 requirements
- 下载 NetMamba 原论文的 Hugging Face checkpoint 到：

```text
external/NetMamba/checkpoints/pre-train.pth
```

注意：对这篇 BiasSeeker 论文的复现来说，上面这个原始 NetMamba checkpoint 只是参考文件，不是最终复现实验直接使用的 checkpoint。

这篇论文重新在下面 6 个公开数据集上预训练了 NetMamba：

- CICIOT2022
- CrossPlatform Android
- CrossPlatform iOS
- ISCXVPN2016
- USTC-TFC2016
- ISCXTor2016

正式复现实验需要生成新的预训练 checkpoint：

```text
outputs/checkpoints/netmamba_reproduced_pretrain/pre-train.pth
```

在任何 NetMamba mitigation fine-tuning 之前，调度器都会先调用：

```text
scripts/pretrain_netmamba_reproduction.sh
```

后续 fine-tuning 会调用：

```text
scripts/run_netmamba_official.sh
```

这个脚本包装了官方 NetMamba 仓库中的 `src/fine-tune.py`。

## 重要：NetMamba 输入格式与原论文不同

这篇 BiasSeeker 论文没有完全沿用 NetMamba 原论文的数据设置。

关键差异是：

- 原 NetMamba 使用单向 flow。
- 这篇论文改成 **双向 session flow**。
- 每个 session 取前 5 个 packet。
- 每个 packet 取：
  - 前 80 个 header bytes
  - 前 240 个 payload bytes
- 是否保留或删除特定 header 字段，要根据 shortcut mitigation 策略决定。

因此，如果缺少按这种方式构造好的 NetMamba 输入，系统会把对应任务标记为失败并等待修复，不会跳过该实验。

## 目录结构

运行过程中会生成下面这些目录：

```text
data/raw/          原始数据集文件
data/interim/      tshark JSON 和扁平化后的 packet 字段
data/processed/    标准化字段、数据划分、模型输入
outputs/state/     可恢复任务状态
outputs/failures/  失败报告和失败清单
outputs/tables/    生成的结果表格
outputs/figures/   生成的图
outputs/logs/      命令日志
reports/           详细复现报告
external/          第三方官方代码，例如 NetMamba
```

## 运行命令

查看当前任务状态：

```bash
python -m biasseeker.cli status
```

运行或继续完整流水线：

```bash
python -m biasseeker.cli run
```

根据当前状态重新生成报告：

```bash
python -m biasseeker.cli report
```

运行测试：

```bash
python -m unittest discover -s tests
```

## 数据集缺失时如何处理

如果某个数据集无法自动下载，系统会把该数据集对应阶段标记为：

```text
awaiting_manual_fix
```

同时生成两个文件：

```text
outputs/failures/<dataset>/<stage>/failure_report.md
outputs/failures/<dataset>/<stage>/failure_manifest.json
```

你需要打开 `failure_report.md`，查看缺少什么文件、应该放到哪个目录。

例如某个数据集要求放到：

```text
data/raw/crossnet2021/
```

那么你手动下载后，把数据集文件放进去，然后重新运行：

```bash
python -m biasseeker.cli run
```

系统会自动检测新文件，并从之前失败的位置继续执行后续步骤。

## 失败不会被跳过

这个工程的设计原则是：失败必须可见，不能偷偷跳过。

下面这些情况都会被记录到失败报告中：

- 数据集自动下载失败
- 数据集缺失
- 文件损坏或格式不对
- 找不到 pcap/pcapng/cap 文件
- `tshark` 解析失败
- 标签文件缺失
- NetMamba 预训练数据缺失
- NetMamba 重新预训练 checkpoint 缺失
- Decision Tree 特征矩阵缺失
- 训练命令失败
- 结果文件缺失

你修复对应问题后，只需要重新运行：

```bash
python -m biasseeker.cli run
```

系统会继续执行未完成部分。

## 输出报告

系统会生成两个主要报告：

```text
reports/reproduction_report.md
reports/application_classification_results.md
```

其中：

- `reproduction_report.md` 是完整复现报告。
- `application_classification_results.md` 是加密应用分类专项报告。

结果表会生成在：

```text
outputs/tables/table_iii_combined.csv
outputs/tables/table_iii_netmamba_only.csv
outputs/tables/table_iii_decision_tree_only.csv
outputs/tables/application_table_combined.csv
outputs/tables/application_table_netmamba_only.csv
outputs/tables/application_table_decision_tree_only.csv
```

其中：

- `combined` 表用于同时对比 NetMamba 和 Decision Tree。
- `netmamba_only` 表只包含 NetMamba。
- `decision_tree_only` 表只包含 Decision Tree。
- `application_*` 表只包含加密应用分类相关结果。

## 复现注意事项

论文没有公开所有实现细节，例如：

- 所有随机种子
- 随机抽样时具体选中的类别
- 作者私有预处理脚本
- 作者重新预训练的 NetMamba checkpoint hash

这个工程不会臆造这些信息，而是会把无法确认的细节写入报告中的 unresolved/deviation 部分。

换句话说：能严格复现的部分会严格复现；论文没有公开、无法确认的部分会明确记录，不会假装完全知道。
