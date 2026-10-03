/* Ghidra Headless Script — Integer Overflow Detection via P-code Analysis

   用法: ghidraHeadless <project_dir> <project_name> \
           -import <binary> \
           -scriptPath <script_dir> \
           -postScript IntOverflowPcode.java <output.json>

   P-code 优势:
     1. INT_AND(val, 0xFFFFFFFF) 显式暴露 32-bit 截断 — 这是 x86 mov [mem], eax 在 P-code 中的形式
     2. INT_SEXT / INT_ZEXT 显式暴露符号/零扩展 — 可追踪类型宽度变化
     3. Varnode 唯一标识 — 跨基本块的数据流追踪无需寄存器重命名
     4. CALL 指令的参数映射 — 直接获取 call site 的输入 Varnode
*/

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.*;
import java.util.*;

public class IntOverflowPcode extends GhidraScript {

    // alloc 函数名 -> size 参数索引 (x86-64: rcx=0, rdx=1, r8=2)
    private static final Map<String, Integer> ALLOC_FUNCS = Map.of(
        "malloc", 0,
        "calloc", 1,   // rdx = size (rcx = nmemb)
        "realloc", 1,  // rdx = size (rcx = ptr)
        "_malloc", 0
    );

    // 检测模式
    private static class Finding {
        String type;
        long addr;
        String func;
        long value;
        double confidence;
        String desc;

        Finding(String t, long a, String f, long v, double c, String d) {
            type = t; addr = a; func = f; value = v; confidence = c; desc = d;
        }
    }

    private List<Finding> findings = new ArrayList<>();

    @Override
    public void run() throws Exception {
        long t0 = System.currentTimeMillis();

        Program program = getCurrentProgram();
        Listing listing = program.getListing();
        FunctionManager funcMgr = program.getFunctionManager();

        // 遍历所有函数
        for (Function func : funcMgr.getFunctions(true)) {
            analyzeFunction(func, listing);
        }

        long elapsed = System.currentTimeMillis() - t0;

        // 输出 JSON 结果
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"binary\": \"" + program.getName() + "\",\n");
        json.append("  \"findings\": " + findings.size() + ",\n");
        json.append("  \"time_ms\": " + elapsed + ",\n");
        json.append("  \"details\": [\n");
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            json.append("    {");
            json.append("\"type\":\"" + f.type + "\",");
            json.append("\"addr\":\"0x" + Long.toHexString(f.addr) + "\",");
            json.append("\"func\":\"" + f.func + "\",");
            json.append("\"val\":\"0x" + Long.toHexString(f.value) + "\",");
            json.append("\"conf\":" + f.confidence + ",");
            json.append("\"desc\":\"" + f.desc + "\"");
            json.append("}");
            if (i < findings.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("  ]\n");
        json.append("}\n");

        // 写入文件
        String outPath = getScriptArgs().length > 0
            ? getScriptArgs()[0]
            : program.getName() + "_int_overflow.json";
        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {
            pw.println(json.toString());
        }
        println("INT-SCAN complete: " + findings.size() + " findings in " + elapsed + "ms");
        println("Output: " + outPath);
    }

    private void analyzeFunction(Function func, Listing listing) {
        // 获取函数的 P-code (高IL)
        // P-code 操作: INT_ADD, INT_SUB, INT_MULT, INT_LEFT, INT_RIGHT,
        //              INT_AND, INT_OR, INT_SEXT, INT_ZEXT, CALL, STORE, LOAD

        for (Instruction insn : listing.getInstructions(func.getBody(), true)) {
            // P-code 获取方式: 通过 instruction.getPcode()
            PcodeOp[] pcode = insn.getPcode();
            if (pcode == null) continue;

            for (int i = 0; i < pcode.length; i++) {
                PcodeOp op = pcode[i];

                // 检测模式: INT_AND(val, 0xFFFFFFFF) -> 32-bit 截断
                // P-code 中 movabs rax, >2^32 -> 后续 INT_AND 或 COPY
                if (op.getOpcode() == PcodeOp.INT_AND) {
                    Varnode constVn = op.getInput(1);
                    if (constVn.isConstant()) {
                        long mask = constVn.getOffset();
                        if (mask == 0xFFFFFFFFL) {
                            // 这是 32-bit 截断操作
                            // 检查 input(0) 的值是否 > 2^32
                            Varnode srcVn = op.getInput(0);
                            if (srcVn.isConstant() && srcVn.getOffset() > 0xFFFFFFFFL) {
                                // 截断链: movabs >2^32 -> INT_AND -> alloc
                                findings.add(new Finding(
                                    "TRUNCATION_PCODE",
                                    insn.getAddress().getOffset(),
                                    func.getName(),
                                    srcVn.getOffset(),
                                    0.85,
                                    "P-code INT_AND truncation: 0x" +
                                    Long.toHexString(srcVn.getOffset()) +
                                    " -> 0x" + Long.toHexString(srcVn.getOffset() & 0xFFFFFFFFL)
                                ));
                            }
                        }
                    }
                }

                // 检测模式: CALL malloc/calloc/realloc
                if (op.getOpcode() == PcodeOp.CALL) {
                    Varnode targetVn = op.getInput(0);
                    if (targetVn.isAddress()) {
                        Symbol sym = getSymbolAt(targetVn.getAddress());
                        if (sym != null && ALLOC_FUNCS.containsKey(sym.getName())) {
                            int sizeIdx = ALLOC_FUNCS.get(sym.getName());
                            // 在此可进一步分析 size 参数的 Varnode 值区间
                            // 实现需要 Varnode 可达性分析 (类似 VSA)
                        }
                    }
                }

                // 检测模式: INT_SEXT -> 符号扩展 (后续可能跟 INT_ADD/INT_MULT)
                // 结合 PcodeOp.INT_LEFT (shl) 检测: INT_LEFT(v, N>=5) + INT_SEXT
                if (op.getOpcode() == PcodeOp.INT_SEXT) {
                    // 查找输入是否为 INT_LEFT (shl) 的结果
                    Varnode inputVn = op.getInput(0);
                    // 完整实现需要遍历 def-use chain
                    // P-code 中每个 Varnode 有唯一的定义点
                }
            }
        }
    }
}
