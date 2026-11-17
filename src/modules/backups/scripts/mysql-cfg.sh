PW=$(printf '%s' "$NT_PASS" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
printf '[client]\nuser=%s\npassword="%s"\n' "$USER_" "$PW" >"$WORK/cfg"
