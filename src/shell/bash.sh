# Bash 3.2-compatible protocol. fd 3 is input; fd 4 carries completion frames.
exec 3<&0 4>&1
while IFS='|' read -r __ss_marker __ss_encoded <&3; do
    builtin printf -v __ss_script '%b' "$__ss_encoded"
    builtin eval -- "$__ss_script" </dev/null 1>&1 2>&1 3<&- 4>&-
    __ss_ec=$?
    builtin printf '\036%s|%s\037' "$__ss_marker" "$__ss_ec" >&4
done
