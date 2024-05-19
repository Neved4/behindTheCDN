#!/usr/bin/env bash
#set -Cefu

     exe_ver=3.0.0
  repo_owner=Neved4
dns_resolver=8.8.8.8

 exe_dir=${0%/*}
exe_name=${0##*/}
conf_dir="$exe_dir/../conf"
     awk="$exe_dir/colorize.awk"

      fval=
     nflag=false
    domain=
  location=
github_raw="https://raw.githubusercontent.com/$repo_owner/$exe_name/main"

# trap ctrl_c INT

check_curl() {
	curl=false

	case "$@" in
	--from-curl)
		curl=true
	esac
}

check_curl "$@"

setvars2() {
	awk="$exe_dir/colorize.awk"
	cdn_patterns="$conf_dir/cdn_patterns.conf"
	global="$conf_dir/global.conf"
	_global=$global

	if $curl
	then
		awk="$github_raw/main/src/colorize.awk"
		cdn_patterns="$github_raw/main/conf/cdn_patterns.conf"
		global="$github_raw/main/conf/global.conf"
	fi
}

setcolors() {
	 reset='\033[0m'     bold='\033[1m'
	   red='\033[31m'   green='\033[32m' _blue='\033[34m'
	yellow='\033[33m' magenta='\033[35m' _cyan='\033[36m'
	  _gray='\033[37m'
}

colorize() {
	if $curl
	then
		awk "$(curl -fsSL "$awk")"
	else
		[ -f "$awk" ] && awk -f "$awk"
	fi
}

msg() {
	  arg=$1 && shift 1
	  pre=${arg%% *}
	color=${arg#* }
	bcolor=${bold}${color}

	println "${bcolor}${pre}${reset}${bcolor} $* ${reset}"
}

msg2() {
	  arg=$1 && shift 1
	  pre=${arg%% *}
	color=${arg#* }
	bcolor=${bold}${color}

	println "" "${bcolor}${pre}${reset}${bold}:${reset}${bcolor} $* ${reset}"
}

println() { printf '%b\n' "$@"; }
     ok() { msg "[+] $green" "${green}$*${reset}"; }
   info() { msg "[*] $magenta" "$@"; }
   warn() { msg "[!] $yellow" "${yellow}$*${reset}"; }
    err() { msg2 "error $red" "$@"; } >&2

ctrl_c() {
	info "Exiting in a controlled way"
	exit 0
}

virustotal_owner() {
	ip="$1"

	virustotal_report="$loc_dom/${ip}_virustotal_report.json"
	virustotal_owner="$loc_dom/${ip}_virustotal_owner.txt"

	curl --retry 3 -s -m 5 -k -X GET \
		--url "$url_virustotal/ip_addresses/$ip" \
		--header "x-apikey: $VIRUSTOTAL_API_ID" > "$virustotal_report"

	jq -r '.data.attributes.as_owner' "$virustotal_report" > "$virustotal_owner"

	cat "$virustotal_owner"
}

dns_records() {
	: "${str:=}"

	info "DNS A records $str<$domain>"

	dns_a_records=($(dig +short A "$domain" @"$dns_resolver"))

	for dns_a in "${dns_a_records[@]}"
	do
		case $str in
		'with AS owner')
			println "$dns_a ${str#* }: $(virustotal_owner "$dns_a")" ;;
		*)
			println "$dns_a"
		esac
	done

	println
}

setvars() {
	url_virustotal="https://www.virustotal.com/api/v3"
	url_virustotal_domains="$url_virustotal/domains"
	url_virustotal_hist="$url_virustotal/$domain/historical_ssl_certificates?limit=40"

	loc_dom="$location/$domain"

	vtDoms="$url_virustotal/$loc_dom/resolutions?limit=40"
	vtRes="$loc_dom/virustotal_resolutions.json"
	vtRes_tmp="${vtRes%.*}_tmp.json"
	vtRes_comb="${vtRes%.*}_combined.json"

	vt_url_next="$loc_dom/virustotal_url_next.txt"

	ip_valid="$loc_dom/IP_valid.txt"
	ip_valid_tmp="${ip_valid%.*}_tmp.txt"

	hist_certs="$loc_dom/virustotal_historical_ssl_certs.json"
	hist_certs_tmp="${hist_certs%.*}_tmp.json"
	hist_certs_combined="${hist_certs%.*}_combined.json"

	shodan_search_dom="$loc_dom/shodan_search_domain.json"
}

setvars

virustotal_url_next() {
	curl --retry 3 -s -m 5 -k -X GET \
		--url "$(cat "$vt_url_next")" \
		--header "x-apikey: $VIRUSTOTAL_API_ID"
}

ip_address() { jq -r '.data[].attributes.ip_address' "$@"; }
 tp_sha256() { jq -r '.data[].attributes.thumbprint_sha256'; }
links_next() { jq -r '.links.next'; }

dns_hist() {
	str="${1:-}"
	intensive=false

	[ "$str" = 'intensive' ] && intensive=true

	info "DNS resolution history <$domain>${str}"

	setvars

	curl --retry 3 -s -m 5 -k -X GET --url "$vtDoms" \
		--header "x-apikey: $VIRUSTOTAL_API_ID" > "$vtRes"

	ip_address "$vtRes" > "$loc_dom/IP.txt"

		echo "$loc_dom/IP.txt"
		cat src/../out/scans/matrix.org/IP.txt

	if $intensive
	then
		links_next "$vtRes" > "$vt_url_next"

		while [ -s "$vt_url_next" ]
		do
			virustotal_url_next > "$vtRes_tmp"
			links_next "$vtRes_tmp" > "$vt_url_next"
			ip_address "$vtRes_tmp" >> "$loc_dom/IP.txt"
			jq -s '.[0].data + .[1].data | {data: .}' \
				"$vtRes" "$vtRes_tmp" > "$vtRes_comb"

			mv "$vtRes_comb" "$vtRes"
		done

		rm -rf "$vt_url_next" "$vtRes_tmp"
	fi

	sort "$loc_dom/IP.txt"

	println
}

sha256_certs="$loc_dom/sha256_certs.txt"

certs_hist() {
	str="${1:-}"
	intensive=false

	[ "$str" = 'intensive' ] && intensive=true

	info "SHA256 fingerprint of SSL certificates [VirusTotal] {${str}}"

	curl --retry 3 -s -m 5 -k -X GET --url "$url_virustotal_hist" \
		--header "x-apikey: $VIRUSTOTAL_API_ID" > "$hist_certs"

	if $intensive
	then
		links_next "$hist_certs" > "$vt_url_next"

		while [ -s "$vt_url_next" ]
		do
			virustotal_url_next > "$hist_certs_tmp"
			links_next "$hist_certs_tmp" > "$vt_url_next"
			tp_sha256 "$hist_certs_tmp" >> "$sha256_certs"
			jq -s '.[0].data + .[1].data | {data: .}' \
				"$hist_certs" "$hist_certs_tmp" > "$hist_certs_combined"

			mv "$hist_certs_combined" "$hist_certs"
		done

		rm -rf "$vt_url_next" "$hist_certs_tmp"
	else
		tp_sha256 "$hist_certs" > "$sha256_certs"
	fi

	cat "$sha256_certs"
}

# virustotal_search_IP_certs() {
# 	println "test"
# }

# virustotal_search_IP_subdomains() {
# 	println "test"
# }

censys_query_certs() {
	info "Searching IPs under sha256 hashes of certs where CN=$domain"

	curl --retry 3 -s -X GET -H "Content-Type: application/json" -H "Host: $CENSYS_DOMAIN_API" \
		-H "Referer: $CENSYS_URL_API" -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
		--url "$CENSYS_URL_API/v2/certs/search?q=$domain" \
		| jq -r '.result.hits | .[].fingerprint_sha256' > "$sha256_certs"

	if [ ! -s "$sha256_certs" ]
	then
		err "No certs found in censys"
		return 1
	fi

	sort "$sha256_certs" | while IFS= read -r sha256
	do
		curl --retry 3 -s -X GET -H "Content-Type: application/json" \
			-H "Host: $CENSYS_DOMAIN_API" -H "Referer: $CENSYS_URL_API" \
			-u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
			--url "$CENSYS_URL_API/v2/hosts/search?q=services.tls.certs.leaf_data.\
			fingerprint%3A+$sha256+or+services.tls.certs.chain.fingerprint%3A+$sha256" \
			| jq -r '.result.hits | .[].ip' >> "$loc_dom/IP.txt"
	done

	if [ ! -s "$loc_dom/IP.txt" ]
	then
		err "Censys IP not found for certs"
		return 1
	fi

	cat "$loc_dom/IP.txt"
}

shodan_search () {
	info "Shodan domain search <$domain>"

	if [ ! "$SHODAN_API" ]
	then
		err "Enter Shodan API Key in API.conf"
		return 1
	fi

	shodan_query="$SHODAN_URL_API/shodan/host/search?key=$SHODAN_API&query=$domain"

	_request=$(
		curl --retry 1 -s -m 10 -X GET -H "Content-Type: application/json" \
		-H "Host: $SHODAN_DOMAIN_API" -H "Referer: $SHODAN_URL_API" \
		--url "$shodan_query" | jq | tee "$shodan_search_dom"
	)

	test_ip=$(
		jq -r '.matches[] | select(.ip_str | test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$")) | .ip_str' "$shodan_search_dom" | sort | uniq)

	if [ -z "$test_ip" ]
	then
		err "No results found in Shodan <$domain>"
		return 1
	fi

	println "$test_ip" >> "$loc_dom/IP.txt"
	println "$test_ip"

	println
}

check_ip_list() {
	if [ ! -s "$loc_dom/IP.txt" ]
	then
		err "IP list is empty"
		return 1
	fi
}

case_type() {
	case $type in
	 http) type_u=HTTP  ;;
	https) type_u=HTTPS ;;
	esac

	info "IP line validation [$type_u]"
}

check_lines() {
	type="${1:?}"
	shift 1

	check_ip_list

	output_dir="$loc_dom/valid_${type}"

	mkdir -p "$output_dir"

	set -- -H "$USER_AGENT" -H "$ACCEPT_HEADER" -H "$ACCEPT_LANGUAGE"

	valid=$(
		curl --retry 3 -L -s -m 10 -k -X GET "$@" \
			-H "$CONNECTION_HEADER" "$type://$domain" |
				tee "$output_dir/valid_${type}.html"
	)

	if [ -z "$valid" ]
	then
		err "$type validation failed (Empty original request)"
		return 1
	fi

	case_type

	for test_ip in $(sort "$loc_dom/IP.txt" | uniq)
	do
		test_valid=$(
			curl --retry 1 -L -s -m 1 -k -X GET "$@" -H "$CONNECTION_HEADER" \
				--resolve "*:80:$test_ip $type://$domain" |
				tee "$output_dir/test_valid_${type}_${test_ip}.html"
		)

		if [ -z "$test_valid" ]
		then
			println "$test_ip Percentage: 0%"
			continue
		fi

		re='(?<=<title>).*?(?=</title>)'

		_file="$output_dir/valid_${type}.html"
		title_a=$(grep -oP "$re" "$_file")

		_file="$output_dir/test_valid_${type}_$test_ip.html"
		title_b=$(grep -oP "$re" "$_file")

		if [ -n "$title_a" ] && [ -n "$title_b" ]
		then
			case "$title_b" in
			*"$title_a"*)
				println "$test_ip Percentage: 100%"
				println "$test_ip" >> "$ip_valid_tmp"
				continue
			esac
		fi

		difference=$(
			{
				println "$valid"
				println "$test_valid"
			} | diff -U 0 /dev/stdin /dev/stdin | grep -ac -v ^@
		) 2> /dev/null

		lines=$(println "$valid" "$test_valid" | wc -l) 2> /dev/null

		if [ "$lines" -eq 0 ]
		then
			println "$test_ip Percentage: Not Applicable%"
			continue
		fi

		percent=$(( (lines - difference) * 100 / lines ))
		percent=$(( percent < 0 ? 0 : percent ))

		println "$test_ip Percentage: ${percent}%"

		[ $percent -gt 75 ] && println "$test_ip" >> "$ip_valid_tmp"
	done

	println
}

normalize_html() {
	file_path=$1 text=

	text=$(xmllint --html --xpath "//text()" "$file_path" 2>/dev/null |
		tr '[:upper:]' '[:lower:]' | awk '{$1=$1};1')

	println "$text"
}

match_percent() {
	text_first=$1
	text_second=$2

	words_first=$(println "$text_first" | tr ' ' '\n')
	words_second=$(println "$text_second" | tr ' ' '\n')

	words_shared=$(println "$words_first" "$words_second" | sort | uniq -d | wc -l)
	 words_total=$(println "$words_first" "$words_second" | sort | uniq | wc -l)

	match=$(
		awk -v c="$words_shared" -v t="$words_total" '
			BEGIN { print (c / t) * 100 }
		'
	)
	integer_match=$(printf "%.0f" "$match")

	println "$integer_match"
}

check_content() {
	type="${1:?}"
	shift 1

	check_ip_list

	input_dir="$loc_dom/valid_${type}"

	if [ ! -d "$input_dir" ]
	then
		err "${type} validation failed (Empty original request)"
		return 1
	fi

	text_first=$(normalize_html "$input_dir/valid_${type}.html" |
		tee "$input_dir/real_normalize_${type}.txt")

	case_type

	re='([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.html/\1/'

	println
	println '-- HTML content match --'

	for file in "$input_dir"/test_valid_"${type}"_*.html
	do
		if [ -f "$file" ]
		then
			filename="${file##*/}"

			test_ip=$(println "$filename" |
				sed -E "s/test_valid_${type}_$re")

			text_second=$(normalize_html "$input_dir/$filename" |
				tee "$input_dir/test_normalize_${type}_$test_ip.txt")

			match=$(match_percent "$text_first" "$text_second")

			if [ "$match" -gt 75 ]
			then
				println "$test_ip" >> "$ip_valid_tmp"
			fi

			printf "%-15s %s\n" "$test_ip" "${match}%"
			# println "$test_ip match: ${match}%"
		fi
	done

	println
}

sort_uniq_file() {
	 in="$1"
	out="$2"

	[ ! -s "$in" ] && return 1

	sort "$in" | uniq > "$out"
}

sort_uniq_ip() {
	sort_uniq_file "$ip_valid_tmp" "$ip_valid"
}

trim_ips_file() {
	file=$1

	[ ! -s "$file" ] && return 1

	for ip_to_delete in "${dns_a_records[@]}"
	do
		sed -i "/^$ip_to_delete$/d" "$file"
	done
}

check_ip() {
	if ! [ -s "$ip_valid" ]
	then
		err "IP list is valid but empty"
		return 1
	fi
}

show_ip() {
	info "Valid IP set"

	check_ip
	cat "$ip_valid"

	println
}

show_ip_owner() {
	info "Valid IP with its Autonomous System owner"

	check_ip

	while IFS= read -r ip
	do
		println "$ip Autonomous System owner: $(virustotal_owner "$ip")"
	done < "$ip_valid"
}

cdn_valid_ptr() {
	IP=$1
	hostname=$(dig +short -x "$IP")

	for cdn in "${cdns[@]}"
	do
		case $hostname in
		*"$cdn"*)
			println "$IP CDN detected by PTR register: $cdn"
			break
		esac
	done
}

cdn_valid_whois() {
	IP=$1
	whois=$(whois "$IP")

	for cdn in "${cdns[@]}"
	do
		case $whois in
		*"$cdn"*)
			println "$IP CDN detected by whois: $cdn "
			break
		esac
	done
}

cdn_valid_headers_cookies() {
	IP=$1

	headers=$(curl --retry 3 -L -sI -m 5 -k -X GET \
		-H "$USER_AGENT" -H "$ACCEPT_HEADER" -H "$ACCEPT_LANGUAGE" \
		-H "$CONNECTION_HEADER" --resolve "*:443:${IP} https://${domain}")

	detected_cdn=

	while IFS= read -r cdn
	do
		str=$cdn
		trim="${str#"${str%%[! ]*}"}"
		pattern="${trim#* }"

		case $headers in
		*$pattern*)
			detected_cdn=$cdn
			break
		esac
	done < "$cdn_patterns"

	if [ -n "$detected_cdn" ]
	then
		println "$IP CDN detected by headers and cookies name: $detected_cdn"
		return 0
	fi

	ok "$IP Potential CDN bypass"
	println "$IP" >> "$results_file"
	println "$IP" >> "$loc_dom/IP_Bypass.txt"
}

check_cdn() {
	info "Searching for CDN"

	check_ip

	while IFS= read -r cdn_search
	do
		cdn_ptr=$(cdn_valid_ptr "$cdn_search")
		if [ -z "${cdn_ptr}" ]
		then
			cdn_whois=$(cdn_valid_whois "$cdn_search")
			if [ -z "${cdn_whois}" ]
			then
				cdn_headers_validation=$(
					cdn_valid_headers_cookies "$cdn_search"
				)

				println "$cdn_headers_validation"
			else
				println "$cdn_whois"
			fi
		else
			println "$cdn_ptr"
		fi
	done < "$ip_valid"

	println
}

waf_detect_shodan() {
	[ -z "$SHODAN_API" ] && return 1

	IP=$1

	shodan_search_ip="$loc_dom/shodan_search_$IP.json"
	shodan_request="$SHODAN_URL_API/shodan/host/$IP?key=$SHODAN_API"

	request=$(
		curl --retry 1 -s -m 10 -X GET \
			-H "Content-Type: application/json" -H "Host: $SHODAN_DOMAIN_API" \
			-H "Referer: $SHODAN_URL_API" \
			--url "$shodan_request" |
				jq | tee "$shodan_search_ip"
	)

	: "$request"

	cdn=$(jq -r 'select(.tags[] | contains("cdn")).data[].isp' \
		"$shodan_search_ip" | sort | uniq)

	waf=$(jq -r '.data[].http.waf' "$shodan_search_ip" | sort | uniq)

	if [ -z "$waf" ] || [ "$waf" = "null" ]
	then
		return 0
	fi

	println "$waf"
}

check_waf() {
	[ ! -s "$ip_valid" ] && return 1

	info "Looking up the WAF in Shodan"

	for waf_search in $(sort "$ip_valid" | uniq)
	do
		waf_valid=$(waf_detect_shodan "$waf_search")

		if [ -n "$waf_valid" ]
		then
			println "$waf_search WAF detected by shodan: $waf_valid"
		else
			ok "$waf_search Potential WAF bypass by Shodan"
		fi
	done
}

core_exec() {
	  check_lines http
	  check_lines https
	check_content http
	check_content https
	 sort_uniq_ip
}

check_cdn_waf() {
	check_cdn
	check_waf
}

core2_exec() {
	censys_query_certs
	shodan_search
	core_exec
	trim_ips_file "$ip_valid"
}

flag_domain() {
	dns_records
	dns_hist
	shodan_search
	check_lines   https
	check_content https
	sort_uniq_ip
	trim_ips_file "$ip_valid"
	show_ip
	check_cdn_waf
}

iflag() {
	dns_records 'with AS owner'
	dns_hist    intensive
	certs_hist  intensive
	shodan_search
	core_exec
	trim_ips_file "$ip_valid"
	show_ip_owner
	check_cdn_waf
}

cflag() {
	dns_records
	dns_hist
	certs_hist
	core2_exec
	show_ip
	check_cdn_waf
}

flag_all() {
	dns_records 'with AS owner'
	dns_hist intensive
	certs_hist intensive
	core2_exec
	show_ip_owner
	check_cdn_waf
}

check_dns_a_records() {
	dns_a_records_check=$(dig +short A "$domain" @${dns_resolver})

	if [ -z "$dns_a_records_check" ]
	then
		err "No resolution DNS found for $domain"
		return 1
	fi
}

exec_scan() {
	timestamp="$(date +%F)"
	mkdir -p out/results

	results_file="$exe_dir/../out/results/results-$timestamp-$domain.txt"

	println "Potential CDN Bypass for: $domain" >> "$results_file"

	: topdomain="$(println "$domain" | awk -F '.' '{ print $(NF-1)"."$NF }')"

	mkdir -p out/scans

	location="$exe_dir/../out/scans"
	scan_path="scans"

	if [ ! -d "$loc_dom" ]
	then
		mkdir "$scan_path/$domain"
	else
		rm -rf "${loc_dom:?}/*"
	fi

	check_dns_a_records

	if [ "$iflag" = true ]
	then
		if [ "$cflag" = true ]
		then
			flag_all
		else
			iflag
		fi
	else
		if [ "$cflag" = true ]
		then
			cflag
		else
			flag_domain
		fi
	fi

	println "" >> "$results_file"
}

main_logic() {
	if [ -n "$oval" ]
	then
		exec_scan | tee -a "$oval"
		return 0
	fi

	exec_scan
}

hascolor() {
	if [ -t 1 ] # && [ $nflag = false ]
	then
		return 0
	else
		return 1
	fi
}

logo() {
	hascolor && printf '%b' "${bold}${yellow}"
	println "██╗  $exe_name" \
	        "╚▊▊╗" \
	        " ╚██ version: $exe_ver"
	hascolor && printf '%b\n' "${reset}"
}

usage() {
	println "usage: $exe_name [-ci] [-d domain | -f file] [-o output] ..." "" \
		"Options:" \
		"  -d  domain    Search domain" \
		"  -f  file      Search domains in file" \
		"  -o  output    Write to file output" \
		"  -K  key1:key2 Enter keys separated by colon" \
		"" \
		"  -c  Enable Censys search" \
		"  -h  Enable DNS history search [Default]" \
		"  -m  Enable subdomain search" \
		"  -n  Disable printing colors" \
		"  -s  Enable SSL certificate search" \
		""
		# VIRUSTOTAL_API_ID:CENSYS_API_ID:CENSYS_API_SECRET:SHODAN_API"
}

print_usage() {
	if hascolor
	then
		usage 2>&1 | colorize
	else
		usage 2>&1
	fi

	exit 1
} 2>&1

has() {
	cmd="${1:?has: cmd not set}"

	command -v "$cmd" >/dev/null
}

hascmd() {
	for i in "$@"
	do
		if ! has "$i"
		then
			err "$i: command not found"
			printf '%s\n' "Please install $i"
			exit 1
		fi
	done
}

isfile() {
	path="$1"

	[ ! -e "$path" ] && err "$path: No such file or directory" && return 1
	  [ -d "$path" ] && err "$path: Is a directory." && return 1
	[ ! -r "$path" ] && err "$path: Permission denied." && return 1
	  [ -f "$path" ] && return 0
}

srcfile() {
	file=${1:?}

	# shellcheck disable=SC1090,SC1091
	[ -f "$file" ] && . "$file"
}

xdg_config() {
	 name=${1:?}
	  xdg=${2:?}
	first=${name%% *}

	xdg_file=$xdg/$exe_name/$first.conf

	for file in $xdg_file $conf_dir/$first.conf
	do
		if srcfile "$file"
		then
			info "Loaded $name from $file"
			break
		fi
	done
}

check_xdg() {
	: "${XDG_CONFIG_HOME:=$HOME/.config}"
	: "${XDG_DATA_HOME:=$HOME/.local/share}"

	xdg_config 'API keys' "$XDG_DATA_HOME"
	xdg_config   'global' "$XDG_CONFIG_HOME"

	srcfile "$conf_dir"/.env && info "Loaded env from $conf_dir/.env"
	println
}

optparse() {
	iflag=false cflag=false domain='' oval='' fval=''

	while getopts ':d:icf:o:nh?' opt
	do
		case "${opt}" in
		d) domain=$OPTARG ;;
		i) iflag=true ;;
		c) cflag=true ;;
		n) nflag=true ;;
		f) fval=$OPTARG ;;
		o) oval=$OPTARG ;;
		?) print_usage ;;
		esac
	done
}

check_api() {
	if [ -z "$VIRUSTOTAL_API_ID" ] || [ -z "$CENSYS_API_ID" ] || [ -z "$CENSYS_API_SECRET" ]
	then
		err "Enter VirusTotal and Censys API Key in API.conf"
		exit 1
	fi
}

main() {
	hascolor && setcolors

	logo

	optparse "$@"
	shift $((OPTIND - 1))

	hascmd 'curl' 'dig' 'jq' 'xmllint'

	# if [ -z "$VIRUSTOTAL_API_ID" ]
	# then
	# 	read -r VIRUSTOTAL_API_ID
	# 	printf %s 'Enter VIRUSTOTAL_API_ID: '
	# fi

	# ###### ^ if no config files are there, ask them interactively using read -r

	# -k VIRUSTOTAL_API_ID=value CENSYS_API_ID=value CENSYS_API_SECRET=value SHODAN_API=value

	if [ -z "$domain" ] && [ -z "$fval" ]
	then
		err "No domain [-d] or file [-f] argument supplied"
		print_usage
	fi

	check_xdg

	[ -n "$fval" ] && isfile "$1"

	check_api

	[ -n "$domain" ] && main_logic "$domain" && return 0

	while IFS= read -r domain
	do
		main_logic "$domain"
	done < "$fval"
}

main "${1+"$@"}"

# ctrl_c
