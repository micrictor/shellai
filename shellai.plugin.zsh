# shellai zsh integration. Source this file after placing `shellai` on PATH.

function _shellai_replace_buffer() {
  local request="$1"
  local context="$2"
  local result

  zle -M 'shellai: generating command…'
  if [[ -n "$context" ]]; then
    result="$(command shellai ask --context "$context" -- "$request")"
  else
    result="$(command shellai ask -- "$request")"
  fi
  local status=$?
  if (( status != 0 )); then
    zle -M 'shellai: generation failed (see error above)'
    return $status
  fi

  BUFFER="$result"
  CURSOR=${#BUFFER}
  zle -R
}

function shellai-hotkey() {
  local original="$BUFFER"
  local requirement

  autoload -Uz read-from-minibuffer
  read-from-minibuffer '🤖 shellai: '
  requirement="$REPLY"
  REPLY=''
  [[ -z "$requirement" ]] && return 0
  _shellai_replace_buffer "$requirement" "$original"
}

function shellai-accept-line() {
  if [[ "$BUFFER" == 'ai,' || "$BUFFER" == 'ai,'[[:space:]]* ]]; then
    local request="${BUFFER#ai,}"
    request="${request#"${request%%[![:space:]]*}"}"
    if [[ -z "$request" ]]; then
      zle -M 'usage: ai, <request>'
      return 1
    fi
    _shellai_replace_buffer "$request" ''
  else
    zle .accept-line
  fi
}

# Also useful from scripts; interactive `ai, ...` is intercepted before execution.
function ai,() {
  command shellai ask -- "$@"
}

if [[ -o interactive ]]; then
  zle -N shellai-hotkey
  zle -N shellai-accept-line

  bindkey "${SHELLAI_HOTKEY:-\\ea}" shellai-hotkey
  bindkey -M emacs '^M' shellai-accept-line
  bindkey -M emacs '^J' shellai-accept-line
  bindkey -M viins '^M' shellai-accept-line
  bindkey -M viins '^J' shellai-accept-line
fi
