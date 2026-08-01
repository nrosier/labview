/**
 * `hashpw` — turn a password into a passwd-file line.
 *
 * ```
 * node dist/hashpw.js alice >> /config/passwd
 * ```
 *
 * **The password is never an argument.** `ps`, `/proc`, a shell history file and every
 * process-listing tool on the host can see a command line, so it is prompted for with
 * the terminal's echo turned off, or read from stdin when there is no terminal. There is
 * no flag to pass it inline, deliberately — a convenience flag here would be the thing
 * everybody's documentation copies.
 *
 * Prompts, warnings and errors go to **stderr** and only the finished line goes to
 * stdout, so the redirect above appends exactly one line and nothing else.
 *
 * `htpasswd -nbB alice password` produces an equivalent line and LabView accepts it;
 * this exists so an operator who has no `htpasswd` — the usual case inside a container —
 * is not stuck.
 */
import { isValidUsername } from "./model/access.js";
import { DEFAULT_COST, hashPassword, passwordTruncates } from "./auth/hash.js";

const USAGE = `usage: node dist/hashpw.js [username] [--cost N]

Prints a "user:hash" line for /config/passwd. The password is prompted for with
echo off, or read from stdin when stdin is not a terminal:

  node dist/hashpw.js alice >> /config/passwd
  printf '%s' "$PW" | node dist/hashpw.js alice

  --cost N   bcrypt cost, 4-31 (default ${DEFAULT_COST}). Higher is slower to verify.
`;

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stderr.write(USAGE);
    return 0;
  }

  let cost = DEFAULT_COST;
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? "";
    if (arg === "--cost") {
      const value = Number(argv[++i]);
      if (!Number.isFinite(value) || value < 4 || value > 31) {
        process.stderr.write("--cost must be a number between 4 and 31\n");
        return 2;
      }
      cost = Math.floor(value);
      continue;
    }
    if (arg.startsWith("-")) {
      process.stderr.write(`unknown option ${arg}\n${USAGE}`);
      return 2;
    }
    positional.push(arg);
  }

  const username = positional[0] ?? (await promptVisible("Username: "));
  if (!isValidUsername(username)) {
    process.stderr.write("A username may contain letters, digits and . _ @ - only, up to 64 characters.\n");
    return 2;
  }

  // No terminal means a pipe: read it all and use it verbatim, minus one trailing
  // newline, because `echo` adds one and nobody means it to be part of the password.
  const interactive = process.stdin.isTTY === true;
  let password: string;
  if (interactive) {
    password = await promptHidden("Password: ");
    const again = await promptHidden("Confirm:  ");
    if (password !== again) {
      process.stderr.write("The two passwords do not match.\n");
      return 1;
    }
  } else {
    password = (await readAll()).replace(/\r?\n$/, "");
  }

  if (!password) {
    process.stderr.write("An empty password is not usable.\n");
    return 1;
  }
  if (passwordTruncates(password)) {
    // bcrypt hashes the first 72 bytes and silently ignores the rest, so a passphrase
    // longer than that is weaker than it looks. Said now, while it can still be changed.
    process.stderr.write(
      "warning: bcrypt only uses the first 72 bytes of a password; the rest of this one will be ignored.\n",
    );
  }

  const hash = await hashPassword(password, cost);
  process.stdout.write(`${username}:${hash}\n`);
  return 0;
}

/** Read a line with the terminal echoing normally. */
function promptVisible(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    process.stderr.write(prompt);
    let value = "";
    const stdin = process.stdin;
    stdin.setEncoding("utf8");
    stdin.resume();
    const onData = (chunk: string): void => {
      value += chunk;
      const nl = value.indexOf("\n");
      if (nl < 0) return;
      stdin.off("data", onData);
      stdin.pause();
      resolve(value.slice(0, nl).trim());
    };
    stdin.on("data", onData);
  });
}

/**
 * Read a line with echo off.
 *
 * Raw mode rather than a muted readline, because raw mode is the only way nothing is
 * echoed at all — a muted output stream still lets the terminal's own echo through. The
 * cost is having to handle the keys a line editor would: Enter, backspace and Ctrl-C.
 * Raw mode is restored on every exit path, including the interrupt, since leaving a
 * terminal in raw mode makes the operator's shell unusable.
 */
function promptHidden(prompt: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    process.stderr.write(prompt);
    stdin.setEncoding("utf8");
    stdin.setRawMode?.(true);
    stdin.resume();

    let value = "";
    const finish = (err?: Error): void => {
      stdin.off("data", onData);
      stdin.setRawMode?.(false);
      stdin.pause();
      process.stderr.write("\n");
      if (err) reject(err);
      else resolve(value);
    };
    const onData = (chunk: string): void => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") return finish();
        if (ch === "\u0003") return finish(new Error("cancelled"));
        if (ch === "\u007f" || ch === "\b") {
          value = value.slice(0, -1);
          continue;
        }
        // Every other control character — arrow keys arrive as escape sequences and
        // would otherwise end up inside the password.
        if (ch < " ") continue;
        value += ch;
      }
    };
    stdin.on("data", onData);
  });
}

function readAll(): Promise<string> {
  return new Promise((resolve, reject) => {
    let out = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk: string) => {
      out += chunk;
    });
    process.stdin.on("end", () => resolve(out));
    process.stdin.on("error", reject);
  });
}

main()
  .then((code) => process.exit(code))
  .catch((err: Error) => {
    process.stderr.write(`${err.message}\n`);
    process.exit(1);
  });
