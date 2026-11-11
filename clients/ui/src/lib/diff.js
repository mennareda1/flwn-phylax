/** Turns a unified diff into rows a person can read: file headers dropped, line numbers worked out, added and removed lines marked. */
export function parseDiff(text) {
  const rows = [];
  let oldNo = 0;
  let newNo = 0;
  for (const line of String(text).split('\n')) {
    if (line.startsWith('--- ') || line.startsWith('+++ ')) continue;
    const hunk = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
    if (hunk) {
      oldNo = Number(hunk[1]);
      newNo = Number(hunk[2]);
      rows.push({ kind: 'hunk', text: line });
    } else if (line.startsWith('+')) {
      rows.push({ kind: 'add', text: line.slice(1), newNo: newNo++ });
    } else if (line.startsWith('-')) {
      rows.push({ kind: 'del', text: line.slice(1), oldNo: oldNo++ });
    } else if (line.startsWith(' ')) {
      rows.push({ kind: 'ctx', text: line.slice(1), oldNo: oldNo++, newNo: newNo++ });
    }
  }
  return rows;
}

export const changedLines = (text) => parseDiff(text).filter((row) => row.kind === 'add' || row.kind === 'del').length;
