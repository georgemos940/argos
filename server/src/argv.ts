// which cscli commands may run. shared by argos and the docker proxy, so it imports nothing

// hub items are author/name, nothing that looks like a path
const ITEM = String.raw`[A-Za-z0-9][\w.-]*\/[A-Za-z0-9][\w-]*(?:\.[\w-]+)*`;

const ALLOWED: RegExp[] = [
  /^(bouncers|machines) list$/,
  /^(hub) (list|update|upgrade)( --dry-run| -a)?$/,
  new RegExp(`^simulation (status|enable|disable)( ${ITEM}| --global)?$`),
  /^console (status|enable|disable)( [\w-]+)?$/,
  /^console enroll [\w-]{10,64} --name [\w.-]{1,64}$/,
  /^metrics show appsec$/,
  new RegExp(`^(scenarios|collections|parsers|postoverflows|contexts|appsec-rules|appsec-configs) (list|inspect|install|remove)( ${ITEM})?$`),
  /^allowlists (list|inspect|create|add|remove|delete)( [\w.:/-]+)*( --(description|expiration|comment) .+)?$/,
  /^metrics( show [\w,-]+)?$/,
  /^decisions list$/,
];

export const isAllowed = (line: string) => ALLOWED.some((re) => re.test(line));

const FREE_TEXT = new Set(['--comment', '--description', '--expiration']);
const FLAGS = new Set(['--dry-run', '-a', '--global', '--name', ...FREE_TEXT]);
const PLAIN = /^[\w.:/@,-]+$/;

/**
 * The full argv argos may exec in the crowdsec container. Every word is plain except the one value
 * after a free-text flag, which has to be last, so no extra flag can ride along inside a comment.
 */
export function argvAllowed(cmd: unknown): boolean {
  if (!Array.isArray(cmd) || cmd.length < 2 || cmd.some((x) => typeof x !== 'string') || cmd[0] !== 'cscli') return false;
  let a = cmd.slice(1) as string[];
  if (a.at(-2) !== '--color' || a.at(-1) !== 'no') return false;
  a = a.slice(0, -2);
  if (a.at(-2) === '-o' && a.at(-1) === 'json') a = a.slice(0, -2);

  if (a[0] === 'explain') {
    return a.length === 5 && a[1] === '--log' && a[2].length > 0 && a[2].length <= 8000 && !/[\r\n]/.test(a[2])
      && a[3] === '--type' && /^[\w-]{1,40}$/.test(a[4]);
  }
  if (a[0] === 'machines' && a[1] === 'add') {
    return a.length === 8 && /^[\w.-]{1,64}$/.test(a[2]) && a[3] === '--password' && /^[!-~]{16,128}$/.test(a[4])
      && a[5] === '-f' && a[6] === '/dev/null' && a[7] === '--force';
  }
  for (let i = 0; i < a.length; i++) {
    const freeValue = i === a.length - 1 && i > 0 && FREE_TEXT.has(a[i - 1]);
    if (freeValue) continue;
    if (a[i].startsWith('-') && !FLAGS.has(a[i])) return false;
    // a free-text flag only ever comes right before the last word
    if (FREE_TEXT.has(a[i]) && i !== a.length - 2) return false;
    if (!PLAIN.test(a[i])) return false;
  }
  return isAllowed(a.join(' '));
}
