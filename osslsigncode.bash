# bash completion for osslsigncode                         -*- shell-script -*-
# Copyright (C) 2021-2022 Michał Trojnara <Michal.Trojnara@stunnel.org>
# Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>

bind 'set show-all-if-ambiguous on'
bind 'set completion-ignore-case on'
COMP_WORDBREAKS=${COMP_WORDBREAKS//:}

_comp_cmd_osslsigncode()
{
    local cur prev words cword
    _init_completion || return

    local commands command options timestamps rfc3161

    commands="--help --version -v
        sign add attach-signature extract-signature remove-signature verify"

    timestamps="http://timestamp.digicert.com
        http://time.certum.pl
        http://timestamp.sectigo.com
        http://timestamp.globalsign.com/?signature=sha2"

    rfc3161="http://timestamp.digicert.com
        http://time.certum.pl
        http://timestamp.entrust.net/TSS/RFC3161sha2TS
        http://tss.accv.es:8318/tsa
        http://kstamp.keynectis.com/KSign/
        http://sha256timestamp.ws.symantec.com/sha256/timestamp"


    if ((cword == 1)); then
        COMPREPLY=($(compgen -W "${commands}" -- ${cur}))
    else
        command=${words[1]}
        case $prev in
            -ac | -c | -catalog | -certs | -spc | -key | -pkcs12 | -pass | \
            -readpass | -pkcs11engine | -pkcs11module | -in | -out | -sigin | \
            -n | -CAfile | -CRLfile  | -TSA-CAfile | -TSA-CRLfile)
                _filedir
                return
                ;;
            -h | -require-leaf-hash)
                COMPREPLY=($(compgen -W 'md5 sha1 sha2 sha256 sha384 sha512' \
                    -- "$cur"))
                return
                ;;
            -jp)
                COMPREPLY=($(compgen -W 'low medium high' -- "$cur"))
                return
                ;;
            -t)
                COMPREPLY=($(compgen -W "${timestamps}" -- "$cur"))
                return
                ;;
            -ts)
                COMPREPLY=($(compgen -W "${rfc3161}" -- "$cur"))
                return
                ;;
            -i | -p)
                _known_hosts_real -- "$cur"
                return
                ;;
        esac

        if [[ $cur == -* ]]; then
            # possible options for the command
            options=$(_parse_help "$1" "$command --help" 2>/dev/null)
            COMPREPLY=($(compgen -W "${options}" -- ${cur}))
        fi
    fi

} &&
    complete -F _comp_cmd_osslsigncode osslsigncode

# ex: filetype=sh
