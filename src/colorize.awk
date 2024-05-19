#!/usr/bin/awk -f

function hl(pattern, color) {
	gsub(pattern, bold color "&" reset)
}

BEGIN {
	if (ENVIRON["TERM"] ~ "xterm*|rxvt*|gnome*|screen*|tmux*") {
		reset = "\033[0m";    red = "\033[31m";    blue = "\033[34m"
		 bold = "\033[1m";  green = "\033[32m"; magenta = "\033[35m"
		under = "\033[4m"; yellow = "\033[33m";    cyan = "\033[36m"
	}

	opts = "(-([a-zA-Z]|[a-zA-Z][a-zA-Z])|Options|usage|\\:\\.\\.\\.)"
	args = "(domain|file|output|key1|key2)"
}

NR == 1 {
	hl("(behindTheCDN.sh)", yellow)
	hl(opts, magenta)
	hl(args, yellow)
}

NR <= 6 {
	sub(args, bold yellow "&" reset)
}

NR > 1 {
	hl("key1|key2", yellow)
}

NR > 1 {
	sub(opts, bold magenta "&" reset)
}

{ print }
