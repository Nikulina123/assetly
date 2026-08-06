/**
 * Assetly Inventory Agent – Google Apps Script
 *
 * HOW TO DEPLOY (one-time setup by IT admin):
 *  1. Open your Google Sheet → Extensions → Apps Script
 *  2. Paste this entire file, replacing the default code
 *  3. Click Deploy → New deployment
 *     Type: Web app
 *     Execute as: Me
 *     Who has access: Anyone          ← required so devices can POST
 *  4. Click Deploy → copy the Web App URL
 *  5. Paste that URL into AssetlyAgent_Windows.ps1 AND AssetlyAgent_macOS.sh AND
 *     AssetlyAgent_Linux.sh as APPS_SCRIPT_URL
 *  6. To update: make changes → Deploy → Manage deployments → edit existing → New version
 */

// ── Sheet names ───────────────────────────────────────────────────────────────
const SHEET_NAME     = "Inventory";
const CHANGELOG_NAME = "Change Log";

// ── Inventory columns ─────────────────────────────────────────────────────────
const HEADERS = [
  "Timestamp", "First Name", "Last Name", "Email", "Project",
  "Hostname", "IP Address", "Brand", "Model", "Serial Number",
  "CPU", "RAM", "Storage", "OS"
];

// 0-based column indices for Inventory
const COL = {
  TIMESTAMP:     0,
  FIRST_NAME:    1,
  LAST_NAME:     2,
  EMAIL:         3,
  PROJECT:       4,
  HOSTNAME:      5,
  IP_ADDRESS:    6,
  BRAND:         7,
  MODEL:         8,
  SERIAL_NUMBER: 9,
  CPU:           10,
  RAM:           11,
  STORAGE:       12,
  OS:            13,
};

// ── Change Log columns ────────────────────────────────────────────────────────
const CHANGELOG_HEADERS = ["Timestamp", "Serial Number", "Hostname", "Comment"];

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Current timestamp in Tbilisi time (UTC+4), human-readable.
 * Example: "21 Apr 2026, 14:30:00"
 */
function getTbilisiTimestamp() {
  const now   = new Date();
  const local = new Date(now.getTime() + 4 * 60 * 60 * 1000);

  const months = ["Jan","Feb","Mar","Apr","May","Jun",
                  "Jul","Aug","Sep","Oct","Nov","Dec"];

  const dd  = String(local.getUTCDate()).padStart(2, "0");
  const mon = months[local.getUTCMonth()];
  const yy  = local.getUTCFullYear();
  const hh  = String(local.getUTCHours()).padStart(2, "0");
  const mm  = String(local.getUTCMinutes()).padStart(2, "0");
  const ss  = String(local.getUTCSeconds()).padStart(2, "0");

  return `${dd} ${mon} ${yy}, ${hh}:${mm}:${ss}`;
}

/**
 * Ensures a sheet exists with the given headers and styling, returns it.
 */
function getOrCreateSheet(ss, name, headers, headerBg) {
  let sheet = ss.getSheetByName(name);
  if (!sheet) {
    sheet = ss.insertSheet(name);
  }
  if (sheet.getLastRow() === 0) {
    sheet.appendRow(headers);
    const hdr = sheet.getRange(1, 1, 1, headers.length);
    hdr.setFontWeight("bold")
       .setBackground(headerBg || "#1A2B5A")
       .setFontColor("#FFFFFF")
       .setHorizontalAlignment("center");
    sheet.setFrozenRows(1);
  }
  return sheet;
}

/**
 * Finds the existing Inventory row for a device.
 * Returns { rowNum, values } (1-based sheet row) or null if not found.
 *
 * Match priority:
 *   1. Serial Number  (most reliable)
 *   2. Hostname       (fallback when serial is absent)
 *
 * First Name / Last Name / Email / Project are NOT part of the lookup key —
 * they are compared afterwards to detect ownership changes.
 */
function findExistingRow(sheet, serialNumber, hostname) {
  const lastRow = sheet.getLastRow();
  if (lastRow <= 1) return null; // only header or empty

  const data = sheet.getRange(2, 1, lastRow - 1, HEADERS.length).getValues();

  for (let i = data.length - 1; i >= 0; i--) {
    const sn   = String(data[i][COL.SERIAL_NUMBER]).trim();
    const host = String(data[i][COL.HOSTNAME]).trim();

    if (serialNumber && sn && sn === serialNumber) {
      return { rowNum: i + 2, values: data[i] }; // +2: 1-based + header offset
    }
    if (!serialNumber && hostname && host === hostname) {
      return { rowNum: i + 2, values: data[i] };
    }
  }
  return null;
}

/**
 * Appends one row to the Change Log sheet.
 */
function appendChangeLog(ss, serialNumber, hostname, comment) {
  const sheet = getOrCreateSheet(ss, CHANGELOG_NAME, CHANGELOG_HEADERS, "#2E4057");
  sheet.appendRow([getTbilisiTimestamp(), serialNumber, hostname, comment]);
  sheet.autoResizeColumns(1, CHANGELOG_HEADERS.length);
}

// ── Web App entry point ───────────────────────────────────────────────────────

function doPost(e) {
  try {
    const data = JSON.parse(e.postData.contents);
    const ss   = SpreadsheetApp.getActiveSpreadsheet();

    const invSheet = getOrCreateSheet(ss, SHEET_NAME, HEADERS, "#1A2B5A");

    const sn       = String(data.serial_number || "").trim();
    const hostname = String(data.hostname      || "").trim();
    const now      = getTbilisiTimestamp();

    const newRowValues = [
      data.timestamp     || now,
      data.first_name    || "",
      data.last_name     || "",
      data.email         || "",
      data.project       || "",
      hostname,
      data.ip_address    || "",
      data.brand         || "",
      data.model         || "",
      sn,
      data.cpu           || "",
      data.ram           || "",
      data.storage       || "",
      data.os            || "",
    ];

    const existing = findExistingRow(invSheet, sn, hostname);

    if (!existing) {
      // ── New device: add a full row, no Change Log entry ──────────────────
      invSheet.appendRow(newRowValues);
      invSheet.autoResizeColumns(1, HEADERS.length);

    } else {
      // ── Known device: compare all fields except Timestamp ────────────────
      const allMatch = HEADERS.slice(1).every((_, i) => {
        const col = i + 1; // skip Timestamp (index 0)
        return String(newRowValues[col]).trim() === String(existing.values[col]).trim();
      });

      if (allMatch) {
        // Nothing changed — skip Inventory update, log to Change Log only
        appendChangeLog(ss, sn, hostname,
          `Collected nothing changed – ${now}`);

      } else {
        // Data changed — update the existing Inventory row with fresh values
        newRowValues[COL.TIMESTAMP] = now; // refresh timestamp on update
        invSheet.getRange(existing.rowNum, 1, 1, HEADERS.length)
                .setValues([newRowValues]);
        invSheet.autoResizeColumns(1, HEADERS.length);

        // Log previous owner to Change Log
        const prevFirst = String(existing.values[COL.FIRST_NAME]).trim();
        const prevLast  = String(existing.values[COL.LAST_NAME]).trim();
        appendChangeLog(ss, sn, hostname,
          `Previous Checkin device owner was: ${prevFirst} ${prevLast} – ${now}`);
      }
    }

    return ContentService
      .createTextOutput(JSON.stringify({ status: "ok" }))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (err) {
    return ContentService
      .createTextOutput(JSON.stringify({ status: "error", message: err.message }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}

// Simple health-check (open URL in browser to verify deployment is alive)
function doGet(e) {
  return ContentService.createTextOutput("Assetly Inventory API – OK");
}
