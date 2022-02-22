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
// Helper script for copying arrays to C as their type and not as a byte array.
//@category Clipboard
//@author Andrew J. Strelsky
import java.awt.datatransfer.DataFlavor;
import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.ByteCopier.ProgrammingByteStringTransferable;
import ghidra.program.model.listing.Data;
import ghidra.util.Msg;

import docking.dnd.GClipboard;
import docking.dnd.GenericDataFlavor;

public class CopyArrayGhidraScript extends GhidraScript {

    private static final DataFlavor FLAVOR = createFlavor();

    @Override
    public void run() throws Exception {
        Data data = getDataAt(currentAddress);
        if (!data.isArray()) {
            return;
        }
        String bytes = new StringBuilder("{")
            .append(String.join(", ", new ArrayValueStringIterator(data)))
            .append("};")
            .toString();
        ProgrammingByteStringTransferable res = new ProgrammingByteStringTransferable(bytes, FLAVOR);
        GClipboard.getSystemClipboard().setContents(res, null);
    }

    private static DataFlavor createFlavor() {

		try {
			return new GenericDataFlavor(
				DataFlavor.javaJVMLocalObjectMimeType + "; class=java.lang.String",
				"Local flavor--C++ array");
		}
		catch (Exception e) {
			Msg.error(CopyArrayGhidraScript.class,
				"Unexpected exception creating data flavor for C++ array", e);
		}

		return null;
	}

    private static abstract class AutoIterable<T> implements Iterable<T>, Iterator<T> {

        @Override
        public final Iterator<T> iterator() {
            return this;
        }
    }

    private static class ArrayDataIterator extends AutoIterable<Data> {

        private final Data data;
        private int index;

        public ArrayDataIterator(Data data) {
            this.data = data;
            this.index = 0;
        }

        @Override
        public boolean hasNext() {
            return index < data.getNumComponents();
        }

        @Override
        public Data next() {
            return data.getComponent(index++);
        }

    }

    private class ArrayValueStringIterator extends AutoIterable<String> {

        private final ArrayDataIterator it;

        public ArrayValueStringIterator(Data data) {
            this.it = new ArrayDataIterator(data);
        }

        @Override
        public boolean hasNext() {
            return it.hasNext();
        }

        @Override
        public String next() {
            return it.next().getValue().toString();
        }
    }

}
