#!/bin/bash

RPPID="${$}"

function log() {
    echo "[$(date "+%H:%M:%S.%3N")] ${*}" 1>&2
}

function ltrim() {
    local str="${*}"
    echo "${str#"${str%%[![:space:]]*}"}"
}

function getline() {
    ltrim "$(sed -n "${2}p" "${1}")"
}

function err_handler() {
    echo "[x] Error caught"
    local i=0
    while read -r line func file < <(caller "${i}") ; do
        log "    ${file}:${line}[in ${func}()]:  $(getline "${file}" "${line}")"
        ((++i))
    done
    kill -s TERM -"${RPPID}"
    exit 1
}

trap err_handler ERR

set -eEuo pipefail
#shopt -s inherit_errexit

function determine_nginx_version() {
    grep -aoP '(nginx|openresty)\/\K\d+(\.\d+){2,}(?=( \(.*\)$|$))' "${1}" | uniq
}

function determine_nginx_signature34() {
    local signature34
    signature34=$(grep -aoP '[\d],[\d],[\d],[01]{34}' "${1}" | uniq)
    if [ "${signature34:0:6}" != "8,4,8," ] ; then
        log "[x] The leadings of signature is not supported. Please fix the script!"
        return 1
    fi
    echo "${signature34}"
}

function nginx_signature_only() {
    echo "${1:6}"
}

function nginx_signature_only_at() {
    echo "${1:$((${2} - 1)):1}"
}

function construct_nginx_configure_args() {
    local nginx_signature34="${1}"
    local nginx_configure_args=("--with-http_v2_module")
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 1)" = "1" ] ; then false ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 2)" = "1" ] ; then false ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 3)" = "1" ] ; then nginx_configure_args+=("--with-file-aio") ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 4)" = "1" ] ; then true `#else false ;` ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 5)" = "1" ] ; then true ; else false ; fi
    # --with-epoll?
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 6)" = "1" ] ; then true ; else false ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 7)" = "1" ] ; then true ; else false ; fi
    # --with-ipv6?
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 8)" = "1" ] ; then true ; else false ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 9)" = "1" ] ; then true ; else false ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 10)" = "1" ] ; then true ; else false ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 11)" = "1" ] ; then false ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 12)" = "1" ] ; then true ; else false ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 13)" = "1" ] ; then true `#; else false` ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 14)" = "1" ] ; then true ; else false ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 15)" = "1" ] ; then true ; else false ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 16)" = "1" ] ; then true ; else false ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 17)" = "1" ] ; then false ; fi
    # support NGX_QUIC in the following order: true: --with-compat, --with-http_v3_module ; false: (none)
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 18)" = "1" ] ; then
        if [ "$(nginx_signature_only_at "${nginx_signature34}" 34)" = "0" ] ; then nginx_configure_args+=("--with-http_v3_module") ; fi
    fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 19)" = "1" ] ; then true ; else false ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 20)" = "1" ] ; then true ; else false ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 21)" = "1" ] ; then true ; else false ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 22)" = "1" ] ; then nginx_configure_args+=("--with-threads") ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 23)" = "1" ] ; then true ; else nginx_configure_args+=("--without-pcre") ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 24)" = "1" ] ; then nginx_configure_args+=("--with-http_ssl_module") ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 25)" = "1" ] ; then true ; else false ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 26)" = "1" ] ; then true ; else nginx_configure_args+=("--without-http_gzip_module") ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 27)" = "1" ] ; then true ; else false ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 28)" = "1" ] ; then true ; else false ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 29)" = "1" ] ; then nginx_configure_args+=("--with-http_realip_module") ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 30)" = "1" ] ; then true `#; else false` ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 31)" = "1" ] ; then nginx_configure_args+=("--with-http_dav_module") ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 32)" = "1" ] ; then true ; else nginx_configure_args+=("--without-http-cache") ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 33)" = "1" ] ; then true ; else nginx_configure_args+=("--without-http_upstream_zone_module") ; fi
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 34)" = "1" ] ; then nginx_configure_args+=("--with-compat") ; fi
    echo "${nginx_configure_args[@]}"
}

function construct_nginx_configure_cflags() {
    local nginx_signature34="${1}"
    local nginx_configure_cflags=()
    # Manually turn on some internal features when --with-compat is not present but features do.
    if [ "$(nginx_signature_only_at "${nginx_signature34}" 34)" = "0" ] ; then
        if [ "$(nginx_signature_only_at "${nginx_signature34}" 30)" = "1" ] ; then nginx_configure_cflags+=("-DNGX_HTTP_HEADERS=1") ; fi
    fi
    echo "${nginx_configure_cflags[@]}"
}

function obtain_nginx_sources() {
    local nginx_version="${1}"
    local src_tar_url="https://nginx.org/download/nginx-${nginx_version}.tar.gz"
    local extra_tar_flags=("--strip-components=1")
    local src_tar_rel="build4u/${src_tar_url##*/}"
    mkdir -p build4u
    wget --no-verbose --output-document="${src_tar_rel}" "${src_tar_url}"
    local nginx_src_git="build4u/nginx-${nginx_version}"
    if [ ! -f "${nginx_src_git}/configure" ] ; then
        mkdir -p "${nginx_src_git}"
        tar -z -x -f "${src_tar_rel}" -C "${nginx_src_git}" "${extra_tar_flags[@]}"
    fi
    echo "${nginx_src_git}"
}

function build4u_main() {
    log "[!] By the use of this script, you assume no header patches were applied to the Nginx binary."
    log "[!] YOU HAVE BEEN WARNED!!!"
    log
    local nginx_exe="${1}"
    local nginx_version="$(determine_nginx_version "${nginx_exe}")"
    log "[i] Nginx version: ${nginx_version}"
    local nginx_signature34_full="$(determine_nginx_signature34 "${nginx_exe}")"
    local nginx_signature34="$(nginx_signature_only "${nginx_signature34_full}")"
    log "[i] Nginx signature (only): ${nginx_signature34}"

    local nginx_configure_args="$(construct_nginx_configure_args "${nginx_signature34}")"
    local nginx_configure_cflags="$(construct_nginx_configure_cflags "${nginx_signature34}")"
    local nginx_src_dir="$(obtain_nginx_sources "${nginx_version}")"
    local nginx_build_dir="build"
    log "[i] Nginx source dir: ${nginx_src_dir}"
    log "[i] Nginx build dir: ${nginx_build_dir}"

    (module_dir="${PWD}" && cd "${nginx_src_dir}" && ./configure ${nginx_configure_args} "${@:2}" --with-cc-opt="-O2 -ggdb2 -ffunction-sections -fdata-sections ${nginx_configure_cflags}" --with-ld-opt="-Wl,--gc-sections" --with-debug --with-stream=dynamic --builddir="${nginx_build_dir}" --add-dynamic-module="${module_dir}")
    make -C "${nginx_src_dir}" -f "${nginx_build_dir}/Makefile" -j$(nproc) build/ngx_stream_route_module.so

    local module_name="ngx_stream_route_module.so"
    local module_file="${nginx_src_dir}/${nginx_build_dir}/${module_name}"
    objcopy --strip-all "${module_file}" "build4u/${module_name}"
    log "[i] ${module_file} is built"

    local nginx_module_signature34_full="$(determine_nginx_signature34 "${module_file}")"
    local nginx_module_signature34="$(nginx_signature_only "${nginx_module_signature34_full}")"
    if [ "${nginx_signature34}" != "${nginx_module_signature34}" ] ; then
        log "[x] Module does not fit!"
        log "[x]     nginx exe: '${nginx_signature34}'"
        log "[x]     module:    '${nginx_module_signature34}'"
        return 1
    fi
    log "[i] DONE successfully, see build4u/${module_name} for stripped version"
}

build4u_main "${@}"
