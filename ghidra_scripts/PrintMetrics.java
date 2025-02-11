/* ###
 * NOTICE: This computer software was prepared by National Technology &
 * Engineering Solutions of Sandia, LLC, hereinafter the Contractor, under
 * Contract DE-NA0003525 with the Department of Energy/National Nuclear
 * Security Administration (DOE/NNSA). All rights in the computer software are
 * reserved by DOE/NNSA on behalf of the United States Government and the
 * Contractor as provided in the Contract. You are authorized to use this
 * computer software for Governmental purposes but it is not to be released or
 * distributed to the public.
 *
 * NEITHER THE GOVERNMENT NOR THE CONTRACTOR MAKES ANY WARRANTY, EXPRESS OR
 * IMPLIED, OR ASSUMES ANY LIABILITY FOR THE USE OF THIS SOFTWARE. This notice
 * including this sentence must appear on any copies of this computer software.
 */

// Dump some simple metrics about the analysis
import ghidra.app.script.GhidraScript;

import ghidra.program.model.address.AddressSetView;

public class PrintMetrics extends GhidraScript {
    public void run() throws Exception {
        println("Number of instructions: " + currentProgram.getListing().getNumInstructions());
        println("Number of functions: " + currentProgram.getFunctionManager().getFunctionCount());

        // how much "stuff" we maybe didn't find
        AddressSetView execSet = currentProgram.getMemory().getExecuteSet();
        AddressSetView undefinedSet = currentProgram.getListing().getUndefinedRanges(execSet, true, monitor);

        println("Executable bytes: " + execSet.getNumAddresses());
        println("Undefined executable bytes: " + undefinedSet.getNumAddresses());
    }
}
