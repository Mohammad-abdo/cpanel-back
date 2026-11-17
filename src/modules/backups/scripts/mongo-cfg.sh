PW=$(printf '%s' "$NT_PASS" | sed -e "s/'/''/g")
printf "password: '%s'\n" "$PW" >"$WORK/cfg"
