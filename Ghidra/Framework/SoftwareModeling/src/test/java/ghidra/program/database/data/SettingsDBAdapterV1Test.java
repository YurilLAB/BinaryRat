/* Copyright 2026 YurilLAB
 * IP: Apache License 2.0
 * SPDX-License-Identifier: Apache-2.0
 */
package ghidra.program.database.data;

import static org.junit.Assert.*;

import org.junit.Test;

import db.DBHandle;
import db.DBRecord;
import ghidra.util.UniversalIdGenerator;

public class SettingsDBAdapterV1Test {

	@Test
	public void testConcurrentNameLookupOnColdAndReloadedIndex() throws Exception {
		UniversalIdGenerator.initialize();
		DBHandle db = new DBHandle();
		try {
			String tableName = "Data Settings";
			long association = 17;
			long tx = db.startTransaction();
			var writer = new SettingsDBAdapterV1(tableName, db, true);
			DBRecord format = writer.createSettingsRecord(association, "format", "hex", 16);
			db.endTransaction(tx, true);

			var reader = new SettingsDBAdapterV1(tableName, db, false);
			ColdAdapterReaders.assertResults(db, SettingsDBAdapterV1.class,
				() -> reader.getSettingName(format),
				() -> reader.getSettingsRecord(association, "format"), "format", format);

			tx = db.startTransaction();
			DBRecord endian = writer.createSettingsRecord(association, "endian", "big", 1);
			db.endTransaction(tx, true);
			reader.invalidateNameCache();
			ColdAdapterReaders.assertResults(db, SettingsDBAdapterV1.class,
				() -> reader.getSettingsRecord(association, "endian"),
				() -> reader.getSettingName(endian), endian, "endian");

			assertEquals(format, reader.getSettingsRecord(association, "format"));
			assertNull(reader.getSettingsRecord(association, "missing"));
			assertNull(reader.getSettingsRecord(association + 1, "endian"));
		}
		finally {
			db.close();
		}
	}
}
