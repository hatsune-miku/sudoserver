# Bash 3.2-compatible protocol. fd 3 is input; fd 4 is the reliable output/frame
# channel, a private dup of the original stdout that commands cannot reach.
exec 3<&0 4>&1
# `builtin` bypasses any read/printf/eval a command may later define as a function.
while IFS='|' builtin read -r __ss_marker __ss_encoded <&3; do
    builtin printf -v __ss_script '%b' "$__ss_encoded"
    # Route the command's stdout and stderr through fd 4, then close fd 3 and fd 4
    # for its duration: `exec >...` inside a command only rebinds its own fd 1, so
    # the next command still starts attached to the pipe, and the command cannot
    # forge or break the completion frame.
    builtin eval -- "$__ss_script" </dev/null >&4 2>&4 3<&- 4>&-
    __ss_ec=$?
    builtin printf '\036%s|%s\037' "$__ss_marker" "$__ss_ec" >&4
done
