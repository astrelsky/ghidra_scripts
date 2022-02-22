/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2022 Andrew J. Strelsky
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */
// Script to go through the current memory block to create all valid pointers
//@category Data
//@author Andrew J. Strelsky
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.AssertException;

public final class CreatePointerScript extends GhidraScript {

	private int pointerSize;

	@Override
	public void run() throws Exception {
		this.pointerSize = currentProgram.getDefaultPointerSize();
		MemoryBlock block = getMemoryBlock(currentAddress);
		Address addr = block.getStart();
		monitor.initialize(block.getSize() / pointerSize);
		monitor.setMessage("Creating Pointers");
		while (block.contains(addr)) {
			monitor.checkCanceled();
			if (isPointer(addr)) {
				try {
					createData(addr, PointerDataType.dataType);
					println("Pointer created at "+addr.toString());
				} catch (Exception e) {
					// dont care
				}
			}
			try {
				addr = addr.add(pointerSize);
			} catch (AddressOutOfBoundsException e) {
				break;
			} finally {
				monitor.incrementProgress(1);
			}
		}
	}

	private boolean isPointer(Address addr) {
		if (getDataContaining(addr) != null) {
			return false;
		}
		Memory mem = currentProgram.getMemory();
		AddressSetView set = mem.getLoadedAndInitializedAddressSet();
		try {
			Address value = getPointerValue(addr);
			if (!set.contains(value)) {
				return false;
			}
			CodeUnit cu = getInstructionContaining(value);
			if (cu == null) {
				cu = getDataContaining(value);
			}
			if (cu != null && !value.equals(cu.getAddress())) {
				return false;
			}
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	private Address getPointerValue(Address addr) throws Exception {
		Memory mem = currentProgram.getMemory();
		switch (pointerSize) {
			case 4:
				return toAddr(mem.getInt(addr));
			case 8:
				return toAddr(mem.getLong(addr));
			default:
				throw new AssertException();
		}
	}

}
