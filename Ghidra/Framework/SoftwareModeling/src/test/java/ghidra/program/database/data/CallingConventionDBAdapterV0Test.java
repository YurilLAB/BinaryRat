/* Copyright 2026 YurilLAB
 * SPDX-License-Identifier: Apache-2.0
 */
package ghidra.program.database.data;

import static org.junit.Assert.*;

import java.util.Set;
import java.util.concurrent.Callable;

import org.junit.Test;

import db.DBHandle;
import ghidra.util.UniversalIdGenerator;

public class CallingConventionDBAdapterV0Test {

	@Test
	public void testColdReadersSeeStoredNameBeforeAndAfterInvalidation() throws Exception {
		UniversalIdGenerator.initialize();
		DBHandle db = new DBHandle();
		try {
			long tx = db.startTransaction();
			var writer = new CallingConventionDBAdapterV0(db, "", true);
			byte firstId = writer.getCallingConventionId("one", name -> {});
			db.endTransaction(tx, true);
			var reader = new CallingConventionDBAdapterV0(db, "", false);
			assertColdReaders(db, reader, firstId, "one");

			tx = db.startTransaction();
			byte newId = writer.getCallingConventionId("two", name -> {});
			db.endTransaction(tx, true);
			assertNotEquals(firstId, newId);
			reader.invalidateCache();
			assertColdReaders(db, reader, newId, "two");
			assertEquals(Set.of("one", "two"), reader.getCallingConventionNames());
			assertEquals(newId, reader.getCallingConventionId("two", name -> fail("duplicate ID")));
		}
		finally {
			db.close();
		}
	}

	private static void assertColdReaders(DBHandle db, CallingConventionDBAdapterV0 adapter,
			byte id, String expected) throws Exception {
		Callable<String> read = () -> adapter.getCallingConventionName(id);
		ColdAdapterReaders.assertResults(db, CallingConventionDBAdapterV0.class, read, read,
			expected, expected);
	}
}
