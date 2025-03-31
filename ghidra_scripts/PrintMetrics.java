/*
 * Copyright 2025 National Technology & Engineering Solutions of Sandia, LLC
 * (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S.
 * Government retains certain rights in this software.

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *     http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
