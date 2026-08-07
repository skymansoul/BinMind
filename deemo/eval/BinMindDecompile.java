// Ghidra headless decompile script — 反编译所有函数为伪代码, 输出JSON
// 由 ghidra_headless.py 作为 -postScript 调用
// 输出路径通过 Java 系统属性 binmind.output 传入

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import java.io.FileWriter;
import java.io.PrintWriter;

public class BinMindDecompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outputPath = System.getProperty("binmind.output");
        if (outputPath == null) {
            println("ERROR: binmind.output not set");
            return;
        }

        PrintWriter out = new PrintWriter(new FileWriter(outputPath));
        Program program = getCurrentProgram();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        out.println("{");
        out.println("  \"binary\": \"" + program.getName() + "\",");
        out.println("  \"functions\": [");

        boolean first = true;
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            DecompileResults result = decomp.decompileFunction(
                func, 30, getMonitor());
            if (result == null || !result.decompileCompleted()) continue;

            String pseudo = result.getDecompiledFunction().getC();
            // Escape for JSON
            pseudo = pseudo.replace("\\", "\\\\")
                         .replace("\"", "\\\"")
                         .replace("\n", "\\n")
                         .replace("\r", "\\r")
                         .replace("\t", "\\t");

            if (!first) out.println(",");
            first = false;

            out.println("    {");
            out.println("      \"name\": \"" + func.getName() + "\",");
            out.println("      \"address\": " + func.getEntryPoint().getOffset() + ",");
            out.println("      \"pseudocode\": \"" + pseudo + "\"");
            out.print("    }");
        }

        out.println("\n  ]");
        out.println("}");
        out.close();
        decomp.closeProgram(program);
    }
}
