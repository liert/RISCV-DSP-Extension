# RISC-V P 扩展 IDA 插件

IDA Pro 9.5 的 IDAPython 插件。它反汇编两套 RISC-V P（Packed-SIMD）编码，并让含有这些指令的函数能被 Hex-Rays 反编译。

- 草案 0.6：609 条指令，opcode 为 `0x13`、`0x1b`、`0x33`、`0x3b`。助记符形如 `padd.b`、`pli.h`。
- T-Head E907 的 P v0.9：360 条指令，opcode 为 `0x77`。助记符形如 `add64`、`add16`、`kaddh`。

两套编码的 opcode 不重叠，同一条机器码只会落入其中一套。普通整数指令仍由 IDA 自带的 RISC-V 模块处理。`add64` 提升成 64 位加法，其余 P 指令提升成纯函数调用。

## 安装

用 IDA 9.5 自带的 IDAPython 即可，不需要 C++ SDK。

把本仓库接到用户插件目录。不要再往 `plugins` 里单独放一份 `riscv_p.py`，否则会加载两次。

```powershell
git clone https://github.com/liert/RISCV-DSP-Extension.git
New-Item -ItemType Junction -Path "$env:APPDATA\Hex-Rays\IDA Pro\plugins\riscv-p" -Target "$PWD\RISCV-DSP-Extension"
```

重启 IDA 后打开 RISC-V 文件。输出窗口里应出现：

```text
riscv-p: loaded P 0.6 (ec309f35), 609 instructions; P v0.9.11 (1bcac751), 360 instructions.
```

已经分析过的数据库不会自动重解。用 **Edit → Plugins → RISC-V P extension** 重新分析可执行段里现有的代码。新打开的文件会在自动分析时经过这个钩子。

## 反汇编

只属于某一档 XLEN 的指令不会在另一档被认出来。

草案 0.6 来自 [P-ext-proposal.adoc](https://github.com/riscv/riscv-p-spec/blob/ec309f351cb9ec1c0ea6a8e90fc1ffafc7064b42/P-ext-proposal.adoc)，是 [riscv-p-spec](https://github.com/riscv/riscv-p-spec) 的内部评审稿 revision 0.6（Development Milestone，2026-09-28 通过）。`pli.db` 只在 RV32，`pli.w` 只在 RV64。

P v0.9 的编码表来自 [opcodes/riscv-opc.c](https://github.com/ruyisdk/riscv-binutils/blob/1bcac7513f9faa4cd969f8dc7cf2491b6c22d7db/opcodes/riscv-opc.c)，也就是 [riscv-p-spec 的 Historical implementations](https://github.com/riscv/riscv-p-spec#historical-implementations) 里列出的 P v0.9.11 binutils。平头哥公开资料把 E907 的 DSP 标成 P v0.9.4，`add64` 的编码与这张表一致。`add64`、`sub64` 只在 RV32，`clz32` 只在 RV64。字节 `77 17 E6 C0` 按小端读是 `0xC0E61777`，在 RV32 上是 `add64 a4, a2, a4`。

这张 v0.9 表不包含 `bpick`，也不包含 XThead 自定义指令（opcode `0x0B`，例如 `th.addsl`）。`swap16`、`rdov`、`clrov`、`kmada32`、`smbb32` 是汇编别名，反汇编打印它们的规范形式，例如 `pkbt16`。

0.6 的打印方式跟规范的汇编语法一致：寄存器对写偶数寄存器，立即数用十进制，有符号立即数带负号。有符号饱和（`psati.*`、`sati`）的汇编宽度是编码里的 `uimm` 加 1；无符号饱和（`pusati.*`、`usati`）不加 1。寄存器对的编码字段只有 4 位，架构寄存器号是字段左移 1。

v0.9 的寄存器字段是完整的 5 位，打印这个寄存器本身。RV32 上结果或操作数是 64 位寄存器对的指令要求对应寄存器为偶数，奇数编码不认成该指令。汇编里写偶数寄存器，奇数寄存器是高 32 位。RV64 上同一条助记符使用单个寄存器，例如 `kadd64`。立即数是无符号十进制，最低位在指令的第 20 位。

压缩指令后面可以紧跟一条只按 2 字节对齐的 32 位 P 指令。

## 伪代码

`add64` 在 RV32 上是两个寄存器对的 64 位加法。加数的高 32 位为 0 时，Hex-Rays 收成普通的加：

```c
v1 = n40000;
if ( CLINT.MTIMECMP == 0 || (n40000 = 0xFFFFFFFF, CLINT.MTIMECMP == -1) )
  CLINT.MTIMECMP = CLINT.MTIME + v1;
else
  CLINT.MTIMECMP += v1;
```

只使用 `add64` 低 32 位时，高半会被删掉，加法收成 32 位。

其余 P 指令是调用。点号改成下划线，立即数接在名字后面，不作为参数。负数用 `n` 前缀。`srai16.u a0, a0, 7` 变成 `srai16_u_7(...)`，`pli.h a0, -2` 变成 `pli_h_n2()`。Hex-Rays 自己命名局部变量，行尾注释标出寄存器。RV32 上的 64 位寄存器对合成一个 `__int64`，偶数寄存器是低 32 位，奇数寄存器是高 32 位（`SHIDWORD`）。会读旧目标的累加指令，例如 `kmada`、`macc.h00`，把旧目标也当作参数。结果没有被后面指令读到的纯调用会被删掉。

打包运算、饱和和 `vxsat` 不会展开成 C 运算符。调用结果就是该指令写出的寄存器。

## 重新生成编码表

`riscv_p_data.py` 和 `riscv_p09_data.py` 是生成文件，不要手改。

草案 0.6 下载 [P-ext-proposal.adoc](https://github.com/riscv/riscv-p-spec/blob/ec309f351cb9ec1c0ea6a8e90fc1ffafc7064b42/P-ext-proposal.adoc)，然后：

```powershell
python tools\extract_p_encodings.py P-ext-proposal.adoc riscv_p_data.py
```

P v0.9 下载 [opcodes/riscv-opc.c](https://github.com/ruyisdk/riscv-binutils/blob/1bcac7513f9faa4cd969f8dc7cf2491b6c22d7db/opcodes/riscv-opc.c) 和 [opcodes/riscv-opc.h](https://github.com/ruyisdk/riscv-binutils/blob/1bcac7513f9faa4cd969f8dc7cf2491b6c22d7db/opcodes/riscv-opc.h)，然后：

```powershell
python tools\extract_p09.py riscv-opc.c riscv-opc.h riscv_p09_data.py
```

## 测试

编码往返不需要 IDA：

```powershell
python tests\test_decode.py
python tests\test_decode09.py
```

IDA 集成测试必须用 Python 3.11，并且本机已安装、激活 IDA 9.5 的 idalib：

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe" tests\test_ida.py
```

## 许可

插件代码按 MIT 许可使用，见 [LICENSE](LICENSE)。

规范正文版权归 RISC-V International，许可为 CC-BY-4.0。binutils 源码是 GPL。仓库里不附带规范原文，也不附带那两份 C 文件。两张编码表只保存 match、mask 和操作数字段。
