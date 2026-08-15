// ============================================================================
//   Script Ghidra Headless - Exportateur Automatique de Décompilation C
// ============================================================================
//   @author    DSS Security / HackerLab Toolkit
//   @category  Decompilation
//   @keybinding
//   @menupath
//   @toolbar
// ============================================================================

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ExportDecompiledC extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("[*] Initialisation de l'interface du decompileur Ghidra...");

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        String outPath = currentProgram.getName() + "_decompiled.c";
        File outFile = new File(outPath);
        PrintWriter writer = new PrintWriter(new FileWriter(outFile));

        writer.println("/*");
        writer.println(" * Export de decompilation brute Ghidra");
        writer.println(" * Fichier source : " + currentProgram.getName());
        writer.println(" */");
        writer.println();

        FunctionIterator functions = currentProgram.getListing().getFunctions(true);
        int count = 0;

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            if (func.isThunk()) continue;

            println("[+] Decompilation de : " + func.getName());
            DecompileResults results = decompiler.decompileFunction(func, 30, monitor);

            if (results != null && results.decompileCompleted()) {
                writer.println("// ============================================================================");
                writer.println("// Fonction : " + func.getName() + " @ " + func.getEntryPoint());
                writer.println("// ============================================================================");
                writer.println(results.getDecompiledFunction().getC());
                writer.println();
                count++;
            }
        }

        writer.close();
        decompiler.dispose();

        println("[+] Decompilation terminee avec succes ! " + count + " fonctions exportees dans " + outPath);
    }
}
