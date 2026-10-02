// Append-only JSONL audit log. Every request and response that passes
// through the proxy is recorded with the policy decision and reason, one
// JSON object per line, so the log can be tailed, grepped, or shipped to a
// SIEM. Entries are also kept in memory for tests and embedders.

import fs from 'node:fs';

export class AuditLog {
  constructor(filePath = null) {
    this.filePath = filePath;
    this.entries = [];
  }

  write(entry) {
    const record = { ts: new Date().toISOString(), ...entry };
    this.entries.push(record);
    if (this.filePath) {
      fs.appendFileSync(this.filePath, JSON.stringify(record) + '\n');
    }
    return record;
  }
}
