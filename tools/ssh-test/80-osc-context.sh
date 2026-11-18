# What systemd 257's /etc/profile.d/80-systemd-osc-context.sh writes to an
# interactive bash: OSC 3008 context records, ended by ST, when the shell
# starts, before each command line runs and after it. The plugin's shell
# and SCP-only modes read that output and have to see through them.
if [ -n "${BASH_VERSION:-}" ] && [[ $- == *i* ]]; then
    __osc_ctx_id=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
    printf '\033]3008;start=%s;user=%s;hostname=%s;type=shell;cwd=%s\033\\' \
        "$__osc_ctx_id" "$USER" "$HOSTNAME" "$PWD"
    __osc_ctx_cmd=""
    __osc_ctx_precmd() {
        local rc=$?
        if [ -n "$__osc_ctx_cmd" ]; then
            printf '\033]3008;end=%s;exit=%s;status=%s\033\\' "$__osc_ctx_cmd" \
                "$([ $rc -eq 0 ] && echo success || echo failure)" "$rc"
        fi
        __osc_ctx_cmd=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
    }
    PROMPT_COMMAND="__osc_ctx_precmd${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
    PS0='\033]3008;start=${__osc_ctx_cmd};type=command;cwd=${PWD}\033\\'
fi
