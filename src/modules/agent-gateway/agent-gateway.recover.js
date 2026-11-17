/**
 * SSH recovery for an offline NodeTeam exec agent (vercel-clone recover-agent parity).
 * Fixed bash script only — no uploaded payload. Prefers systemd unit `nodeteam-agent`,
 * then PM2 process names that match the agent entrypoint.
 */

/** Trusted recovery script. Args unused. Prints a single JSON object on the last line. */
export const RECOVER_SCRIPT = `set -euo pipefail
UNIT=nodeteam-agent
STEPS=""
add() { STEPS="$STEPS{\\"step\\":\\"$1\\",\\"ok\\":$2,\\"detail\\":\\"$3\\"},"; }
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if sudo -n true >/dev/null 2>&1; then SUDO="sudo -n "; else
    echo '{"ok":false,"failure":"not-root","steps":[],"error":"need root or passwordless sudo"}'
    exit 0
  fi
fi

if command -v systemctl >/dev/null 2>&1 && $SUDO systemctl cat "$UNIT" >/dev/null 2>&1; then
  if $SUDO systemctl is-active --quiet "$UNIT"; then
    add "systemd-active" true "already active"
    $SUDO systemctl restart "$UNIT" >/dev/null 2>&1 && add "systemd-restart" true "restarted" || add "systemd-restart" false "restart failed"
  else
    add "systemd-active" false "inactive"
    $SUDO systemctl start "$UNIT" >/dev/null 2>&1 && add "systemd-start" true "started" || add "systemd-start" false "start failed"
  fi
  ACTIVE=0
  $SUDO systemctl is-active --quiet "$UNIT" && ACTIVE=1
  STEPS="[\${STEPS%,}]"
  if [ "$ACTIVE" = 1 ]; then
    echo "{\\"ok\\":true,\\"method\\":\\"systemd\\",\\"unit\\":\\"$UNIT\\",\\"steps\\":$STEPS}"
  else
    echo "{\\"ok\\":false,\\"failure\\":\\"watchdog-failed\\",\\"method\\":\\"systemd\\",\\"unit\\":\\"$UNIT\\",\\"steps\\":$STEPS,\\"error\\":\\"unit not active after restart\\"}"
  fi
  exit 0
fi

if command -v pm2 >/dev/null 2>&1; then
  NAME=""
  for CAND in nodeteam-agent nodeteam_agent; do
    if pm2 describe "$CAND" >/dev/null 2>&1; then NAME="$CAND"; break; fi
  done
  if [ -z "$NAME" ]; then
    # Last resort: any PM2 app whose script path mentions nodeteam-agent
    NAME=$(pm2 jlist 2>/dev/null | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{try{const a=JSON.parse(d);const h=a.find(x=>String(x?.pm2_env?.pm_exec_path||x?.name||'').includes('nodeteam-agent'));console.log(h?.name||'')}catch{console.log('')}})" || true)
  fi
  if [ -n "$NAME" ]; then
    add "pm2-found" true "$NAME"
    if pm2 restart "$NAME" >/dev/null 2>&1; then
      add "pm2-restart" true "restarted"
      STEPS="[\${STEPS%,}]"
      echo "{\\"ok\\":true,\\"method\\":\\"pm2\\",\\"name\\":\\"$NAME\\",\\"steps\\":$STEPS}"
      exit 0
    fi
    add "pm2-restart" false "restart failed"
    STEPS="[\${STEPS%,}]"
    echo "{\\"ok\\":false,\\"failure\\":\\"watchdog-failed\\",\\"method\\":\\"pm2\\",\\"name\\":\\"$NAME\\",\\"steps\\":$STEPS}"
    exit 0
  fi
fi

echo '{"ok":false,"failure":"agent-not-found","steps":[],"error":"no systemd unit nodeteam-agent and no matching PM2 process"}'
`;

/** Parse the last JSON object printed by RECOVER_SCRIPT. */
export function parseRecoverOutput(stdout) {
  const lines = String(stdout ?? '')
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    if (!lines[i].startsWith('{')) continue;
    try {
      return JSON.parse(lines[i]);
    } catch {
      /* keep looking */
    }
  }
  return null;
}
