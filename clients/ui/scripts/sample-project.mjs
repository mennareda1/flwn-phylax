// The sample project the demo reviews. Small, believable, and deliberately vulnerable. Re-record the demo after changing anything here:  npm run record-demo
// (src/run.js and src/db.ts must keep the exact lines the correction stand-in knows how to fix.)
export const SAMPLE_PROJECT = {
  name: 'sample-app',
  files: {
    'src/run.js': `const { exec } = require("child_process");

// Lists the files in a folder the user picked in the app.
function run(dir) {
  exec(\`ls \${dir}\`);
}

module.exports = { run };
`,
    'src/db.ts': `import { pool } from "./pool";

export function find(id: string) {
  return pool.query(\`SELECT * FROM t WHERE id = \${id}\`);
}
`,
    'src/token.js': `// Makes the code sent in a password-reset email.
function makeResetToken() {
  return Math.random().toString(36).slice(2);
}

module.exports = { makeResetToken };
`,
    'src/config.js': `const awsKey = "AKIAJQ7XWB4HNTRCPLMD";

module.exports = { awsKey, region: "eu-west-1" };
`,
    'config/mail.yaml': `smtp:\n  host: smtp.mailrelay.example\n  port: 587\n  user: notifications\n  password: Sm7p!relay2024\n`,
    'src/ok.js': `const add = (a, b) => a + b;

module.exports = { add };
`,
  },
};
