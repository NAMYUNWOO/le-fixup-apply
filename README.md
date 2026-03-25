# DOS LE Fixup Applier for Ghidra

A Python tool that statically applies LE (Linear Executable) fixup/relocation records to produce a flat binary. Designed specifically to solve Ghidra's decompilation issues with 32-bit DOS/4GW executables (often compiled with Watcom C/C++).

## 🔍 The Problem
When reverse-engineering classic DOS games or applications using Ghidra, the default LE/LX loaders often struggle to process load-time fixups correctly. This results in:
* Broken data references in the decompiler (global variables and strings point to `0x0`).
* Unresolved cross-references.
* Significantly fewer automatically identified functions.

## 💡 The Solution
This script acts as an offline OS loader. It simulates the memory mapping process by:
1. Parsing the LE header, Object Table, and Fixup Tables.
2. Mapping all code and data pages into a single flat virtual memory space (e.g., `.code` at `0x10000`, `.data` at `0xA0000`).
3. Resolving and applying internal fixups (32-bit absolute offsets, self-relative offsets, 16-bit pointers, etc.).
4. Dumping the fully relocated memory image as a raw `.bin` file.

By loading this patched flat binary into Ghidra, you get **perfect data references** and a massive increase in recognized functions.

## 🚀 Usage

**Requirements:** Python 3.x (No external libraries required)

```bash
python le_fixup_apply.py <input.exe> <output.bin>
```

**Example:**
```bash
python le_fixup_apply.py GAME.EXE GAME_relocated.bin
```
The script will output the memory mapping details, the entry point, and the total number of applied fixups. **Take note of the `Memory image` start address and the `Entry point`**, as you will need them for Ghidra.

## 🛠️ Loading into Ghidra (Step-by-Step)

Once you have generated the `output.bin` file, follow these exact steps to load it into Ghidra:

1. **File > Import File...** and select your `output.bin`.
2. Change the **Format** to `Raw Binary`.
3. Click the **Language** `[...]` button and select `x86:LE:32:default` (or `x86:LE:32:System Management Mode`).
4. Click **Options...** and set the **Base Address** to the `Memory image` start address printed by the script (usually `0x10000`).
5. Click **OK** to import.
6. Open the file in the CodeBrowser.
7. Go to **Window > Memory Map** and split/rename the blocks into `.code` and `.data` based on the sizes and base addresses printed by the script. Ensure the `.code` block has Execute (`X`) permissions.
8. Press `G` to go to the **Entry Point** address printed by the script, and press `D` to disassemble.
9. Finally, run **Analysis > Auto Analyze** (all default options).

## ⚠️ Known Limitations
* **Statically Linked Focus:** This tool perfectly resolves internal object references (`tgt_kind == 0x00`). It currently ignores external imports (DLLs) by ordinal or name, as most 32-bit DOS games are statically linked.
* **Large Memory Gaps:** The script allocates a single `bytearray` spanning from the lowest object base to the highest. If an executable has an unusually massive gap between virtual sections (e.g., Object 1 at `0x10000` and Object 2 at `0x80000000`), it may cause a `MemoryError`.

## 🎮 Author's Note

To be completely honest, I'm not a reverse engineering expert at all! I started this project simply because I love games and wanted to try modding some of my favorite classic titles. Through a lot of trial and error, I ended up learning what Watcom C/C++ is and diving deep into the LE (Linear Executable) format. 

It was quite a journey, but I built this in the hopes that it could help other gamers and modders out there. If you're looking to breathe new life into classic DOS games, I really hope this tool makes your life a little easier. Happy modding!


사실 저는 리버싱을 잘 아는 전문가는 아닙니다. 그저 게임을 너무 사랑하고, 고전 게임들을 직접 모딩해보고 싶다는 마음에 맨땅에 헤딩하듯 시작했어요. 이 작업을 하면서 난생처음 Watcom C/C++이 뭔지 알게 되고, LE(Linear Executable) 형식이라는 것도 뜯어보게 되었습니다.

완벽한 코드는 아닐지 몰라도, 저처럼 고전 게임을 사랑하고 모딩의 세계에 뛰어들고 싶은 분들에게 조금이나마 도움이 되었으면 하는 마음으로 공유합니다. 다들 즐겁게 모딩하세요!

## 📜 License
MIT License