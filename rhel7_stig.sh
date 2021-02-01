#!/bin/bash

#-------------------------------------------------------------------------------
# Internal Functions
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# Show Usage Instructions
# Globals:
#   None
# Arguments:
#   None
# Outputs:
#   Writes usage instructions to STDOUT
# Returns:
#  None
#-------------------------------------------------------------------------------
print_usage() {
    echo -e "centos7_stig.sh - Check and STIG a Centos 7 machine

centos7_stig.sh [-e|-f] [-c] <file>

options:
-e      Apply the applicable fixes
-f      Force apply the fix, even if the setting is currently valid

-c      Path to STIG CKL to update
"
}

#-------------------------------------------------------------------------------
# Modifies a given config file
# Globals:
#   None
# Arguments:
#   file - path to config file
#   header - config Section to be modified
#   key - Key to modify in config file
#   value - Value to set
# Outputs:
#   Writes changes to config file
# Returns:
#  None
#-------------------------------------------------------------------------------
function set_config_value() {
    file="$1"
    header="$2"
    key="$3"
    value="$4"

    tmpfile=$(mktemp)
    headerRegex='^\[(\S+)\]$'
    keyRegex="\s*$key\s*"

    in_section=""
    section_found=""
    setting_persisted=""
    IFS=''

    while read -r line
    do
        # Check for the next header
        if [[ "$line" =~ $headerRegex ]]
        then
            # Is it the one we're looking for?
            if [ "$header" == "${BASH_REMATCH[1]}" ]
            then
                in_section="1"
                section_found="1"
            else
                #if the setting hasn't been persisted by now, this is the bottom of the section.  Add new setting key
                if ! [ -n "$setting_persisted" ] && [ -n "$in_section" ]
                then
                    setting_persisted="1"
                    echo "$key=$value" >> "$tmpfile"
                    echo "" >> "$tmpfile"
                    echo "" >> "$tmpfile"
                fi
                in_section=""
            fi
        fi

        # If we are in the right section:
        if [ -n "$in_section" ]
        then
            # and we look at the right key
            if [[ "$line" =~ $keyRegex ]]
            then
                # change it
                line="$key=$value"
                setting_persisted="1"
            fi
        fi

        # Print the line, either as it was or modified
        echo "$line" >> "$tmpfile"
    done < "$file"

    #config section not found, add section and setting to output
    if ! [ -n "$section_found" ]
    then
        echo "" >> "$tmpfile"
        echo "[$header]" >> "$tmpfile"
        echo "$key=$value" >> "$tmpfile"

        setting_persisted="1"
    fi

    #setting not persisted, add setting to output
    if ! [ -n "$setting_persisted" ]
    then
        echo "$key=$value" >> "$tmpfile"
    fi

    mv "$tmpfile" "$file"
}

#-------------------------------------------------------------------------------
# Global Sources
#-------------------------------------------------------------------------------

_template=$(cat <<'EOF'

---------------------------------------------------------------------------------------------------
| $index. Severity: $severity, Vuln Id: $vuln_id, Rule: $rule_id, CCI: $cci
---------------------------------------------------------------------------------------------------
$title

Requirement:
    $requirement

Check Results:
    $check_results

Current Status:
    $current_status

Remediation:
    $remediation

Final Status:
    $final_status

$ckl_verbiage
---------------------------------------------------------------------------------------------------
EOF
)

_update_ckl=$(cat <<EOF
import argparse
import sys
from lxml import etree

parser = argparse.ArgumentParser(description='update ckls')
parser.add_argument('--ckl', required=True, help='ckl to update')
parser.add_argument('--rule', required=True, help='rule to find')
parser.add_argument('--status', required=True, help='status')
parser.add_argument('--comments', required=True, help='comments')
parser.add_argument('--details', required=True, help='finding details')

args = parser.parse_args()

content_file = open(args.ckl, 'r')
data = content_file.read()
content_file.close()

tree = etree.fromstring(data)
node = tree.xpath(".//VULN[./STIG_DATA/ATTRIBUTE_DATA/text()='{}']".format(args.rule))

if len(node) > 0:
    node[0].find('./STATUS').text = args.status
    node[0].find('./COMMENTS').text = args.comments
    node[0].find('./FINDING_DETAILS').text = args.details

    content_file = open(args.ckl, 'w')
    content_file.write(etree.tostring(tree))
    content_file.close()
EOF
)


#-------------------------------------------------------------------------------
# Requirement Functions
#-------------------------------------------------------------------------------
function _v204392 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that the file permissions,
ownership, and group membership of system files and commands match the vendor values."
    local requirement="system files and commands must have default file permissions, ownership, and group membership"
    local vuln_id='V-204392'
    local rule_id='SV-204392r505924_rule'
    local cci='CCI-001494'
    local severity='CAT I'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    files=()
    check_results+="Package Updates Required For:"
    for i in `rpm -Va | egrep -i '^\.[M|U|G|.]{8}' | cut -d " " -f 4,5`;do
        for j in `rpm -qf $i`;do
            rpm=$(rpm -ql $j --dump | cut -d " " -f 1,5,6,7 | grep $i;)
            check_results+="$rpm";
            file=$(echo $rpm | cut -d' ' -f1)
            ls -al $file
            files+=( $file )
        done;
    done

    if [ ${#files[@]} -eq 0 ]; then
        current_status="NotAFinding"
        final_status="NotAFinding"
        final_results="Permissions valid"
    else
        current_status="Open"
        final_status="Open"
        final_results="Permissions require updates"
    fi

    remediation+="Updating permissions for:";
    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ] && [ ${#files[@]} -gt 0 ]; then
        for f in "${files[@]}" ;do
            remediation+="  $f"
            pkg=`rpm -qf $f`
            remediation+="  $pkg"
            rpm --setugids $pkg
            rpm --setperms $pkg
        done;
        final_status="NotAFinding"
        final_results="Permissions Updated"
    fi

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}


function _V204393 (){
    local title="The Red Hat Enterprise Linux operating system must display the Standard Mandatory DoD Notice and
Consent Banner before granting local or remote access to the system via a graphical user logon."
    local requirement="banner-message-enable must be present and not set to false"
    local vuln_id='V-204393'
    local rule_id='SV-204393r505924_rule'
    local cci='CCI-000048'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep --directories=skip banner-message-enable /etc/dconf/db/local.d/*`
    current_status=$( [[ "$check_results" != *"banner-message-enable=true"* ]] && echo "Open" || echo "NotAFinding")

    #Fix requirement if needed
    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ "$check_results" != *"banner-message-enable=true"* ]] || [[ $force_flag == 'true' ]]; then
            touch "/etc/dconf/db/local.d/01-banner-message"
            set_config_value "/etc/dconf/db/local.d/01-banner-message"  "org/gnome/login-screen" "banner-message-enable" "true"
            dconf update
            remediation="Updated settings in /etc/dconf/db/local.d/01-banner-message"
        else
            remediation="Not required"
        fi
    fi

    #check settings again after fix
    final_results=`grep --directories=skip banner-message-enable /etc/dconf/db/local.d/*`
    final_status=$( [[ "$final_results" != *"banner-message-enable=true"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204394 (){
    local title="The Red Hat Enterprise Linux operating system must display the approved Standard Mandatory DoD
Notice and Consent Banner before granting local or remote access to the system via a graphical user
logon."
    local requirement="banner-message-text must be set to the DoD Banner Text"
    local vuln_id='V-204394'
    local rule_id='SV-204394r505924_rule'
    local cci='CCI-000048'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_text="'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\\n-At any time, the USG may inspect and seize data stored on this IS.\\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details. '"

    check_results=`grep --directories=skip  banner-message-text /etc/dconf/db/local.d/*`
    current_status=$( [[ "$check_results" != *"banner-message-text=$check_text"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ "$check_results" != *"banner-message-text=$check_text"* ]] || [[ $force_flag == 'true' ]]; then
            touch "/etc/dconf/db/local.d/01-banner-message"
            set_config_value "/etc/dconf/db/local.d/01-banner-message"  "org/gnome/login-screen" "banner-message-text" "$check_text"
            dconf update
            remediation="Updated settings in /etc/dconf/db/local.d/01-banner-message"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep --directories=skip  banner-message-text /etc/dconf/db/local.d/*`
    final_status=$( [[ "$final_results" != *"banner-message-text=$check_text"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"

}

function _V204395 (){
    local title="The Red Hat Enterprise Linux operating system must display the Standard Mandatory DoD Notice and
Consent Banner before granting local or remote access to the system via a command line user logon."
    local requirement="The Standard Mandatory DoD Notice and Consent Banner must be displayed before granting
access to the operating system via a command line user logon."
    local vuln_id='V-204395'
    local rule_id='SV-204395r505924_rule'
    local cci='CCI-000048'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_text="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

    check_results="$(cat /etc/issue)"
    current_status=$( [[ `echo $check_text | tr -cd '[:alnum:]' | md5sum | awk '{ print $1 }'` != `echo $check_results | tr -cd '[:alnum:]' | md5sum | awk '{ print $1 }'` ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if
            [[ $(cat /etc/ssh/sshd_config | grep "/etc/issue" | wc -c) -eq 0 ]] ||
            [[ `echo $check_text | tr -cd '[:alnum:]' | md5sum | awk '{ print $1 }'` != `echo $check_results | tr -cd '[:alnum:]' | md5sum | awk '{ print $1 }'` ]] ||
            [[ $force_flag == 'true' ]];
        then
            echo -e "$check_text" > /etc/issue

            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"Banner "* ]]; then
                    echo "Banner /etc/issue" >> "$tmpfile"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/ssh/sshd_config

            if [[ $( grep -i banner "$tmpfile" | wc -c) -eq 0 ]]; then
                echo "Banner /etc/issue" >> "$tmpfile"
            fi

            mv "$tmpfile" "/etc/ssh/sshd_config"
            remediation="Updated settings in /etc/ssh/sshd_config"
         else
            remediation="Not required"
        fi
    fi

    final_results="$(cat /etc/issue)"
    final_status=$( [[ `echo $check_text | tr -cd '[:alnum:]' | md5sum | awk '{ print $1 }'` != `echo $final_results | tr -cd '[:alnum:]' | md5sum | awk '{ print $1 }'` ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}


function _V204396 (){
    local title="The Red Hat Enterprise Linux operating system must enable a user session lock until that user
re-establishes access using established identification and authentication procedures."
    local requirement="lock-enabled must be present and not set to false"

    local vuln_id='V-204396'
    local rule_id='SV-204396r505924_rule'
    local cci='CCI-000056'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep --directories=skip lock-enabled /etc/dconf/db/local.d/*`
    current_status=$( [[ "$check_results" != *"lock-enabled=true"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ "$check_results" != *"lock-enabled=true"* ]] || [[ $force_flag == 'true' ]]; then
            touch "/etc/dconf/db/local.d/00-screensaver"
            set_config_value "/etc/dconf/db/local.d/00-screensaver"  "org/gnome/desktop/screensaver" "lock-enabled" "true"
            dconf update
            remediation="Updated settings in /etc/dconf/db/local.d/00-screensaver"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep --directories=skip lock-enabled /etc/dconf/db/local.d/*`
    final_status=$( [[ "$final_results" != *"lock-enabled=true"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"

}

function _V204397 (){
    local title="The Red Hat Enterprise Linux operating system must uniquely identify and must authenticate users
using multifactor authentication via a graphical user logon."
    local requirement="enable-smartcard-authentication must be present and not set to false"

    local vuln_id='V-204397'
    local rule_id='SV-204397r505924_rule'
    local cci='CCI-001948'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep --directories=skip enable-smartcard-authentication /etc/dconf/db/local.d/*`
    current_status=$( [[ "$check_results" != *"enable-smartcard-authentication=true"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ "$check_results" != *"enable-smartcard-authentication=true"* ]] || [[ $force_flag == 'true' ]]; then
            touch "/etc/dconf/db/local.d/00-defaults"
            set_config_value "/etc/dconf/db/local.d/00-defaults"  "org/gnome/login-screen" "enable-smartcard-authentication" "true"
            dconf update
            remediation="Updated settings in /etc/dconf/db/local.d/00-defaults"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep --directories=skip enable-smartcard-authentication /etc/dconf/db/local.d/*`
    final_status=$( [[ "$final_results" != *"enable-smartcard-authentication=true"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204398 (){
    local title="The Red Hat Enterprise Linux operating system must uniquely identify and must authenticate users
using multifactor authentication via a graphical user logon."
    local requirement="enable-smartcard-authentication must be present and not set to false"

    local vuln_id='V-204398'
    local rule_id='SV-204398r505924_rule'
    local cci='CCI-000057'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep --directories=skip idle-delay /etc/dconf/db/local.d/*`
    current_status=$( [[ "$check_results" != *"idle-delay=uint32 900"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ "$check_results" != *"idle-delay=uint32 900"* ]] || [[ $force_flag == 'true' ]]; then
            touch "/etc/dconf/db/local.d/00-screensaver"
            set_config_value "/etc/dconf/db/local.d/00-screensaver"  "org/gnome/desktop/session" "idle-delay" "uint32 900"
            dconf update
            remediation="Updated settings in /etc/dconf/db/local.d/00-screensaver"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep --directories=skip idle-delay /etc/dconf/db/local.d/*`
    final_status=$( [[ "$final_results" != *"idle-delay=uint32 900"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204399 (){
    local title="The Red Hat Enterprise Linux operating system must prevent a user from overriding the screensaver
lock-delay setting for the graphical user interface."
    local requirement="lock-delay must be locked"

    local vuln_id='V-204399'
    local rule_id='SV-204399r505924_rule'
    local cci='CCI-000057'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep --directories=skip lock-delay /etc/dconf/db/local.d/locks/*`
    current_status=$( [[ "$check_results" != *"lock-delay"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ "$check_results" != *"lock-delay"* ]] || [[ $force_flag == 'true' ]]; then
            touch "/etc/dconf/db/local.d/locks/session"

            tmpfile=$(mktemp)
            while read -r line
            do
                if ! [[ $line == *"lock-delay"* ]]; then
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/dconf/db/local.d/locks/session
            echo "/org/gnome/desktop/screensaver/lock-delay" >> "$tmpfile"
            mv "$tmpfile" "/etc/dconf/db/local.d/locks/session"

            dconf update

            remediation="Updated settings in /etc/dconf/db/local.d/locks/session"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep --directories=skip lock-delay /etc/dconf/db/local.d/locks/*`
    final_status=$( [[ "$final_results" != *"lock-delay"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204400 (){
    local title="The Red Hat Enterprise Linux operating system must prevent a user from overriding the session
idle-delay setting for the graphical user interface."
    local requirement="idle-delay must be locked"

    local vuln_id='V-204400'
    local rule_id='SV-204400r505924_rule'
    local cci='CCI-000057'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep --directories=skip idle-delay /etc/dconf/db/local.d/locks/*`
    current_status=$( [[ "$check_results" != *"idle-delay"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ "$check_results" != *"idle-delay"* ]] || [[ $force_flag == 'true' ]]; then
            touch "/etc/dconf/db/local.d/locks/session"
            tmpfile=$(mktemp)
            while read -r line
            do
                if ! [[ $line == *"idle-delay"* ]]; then
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/dconf/db/local.d/locks/session
            echo "/org/gnome/desktop/screensaver/idle-delay" >> "$tmpfile"
            mv "$tmpfile" "/etc/dconf/db/local.d/locks/session"

            dconf update
            remediation="Updated settings in /etc/dconf/db/local.d/locks/session"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep --directories=skip idle-delay /etc/dconf/db/local.d/locks/*`
    final_status=$( [[ "$final_results" != *"idle-delay"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204402 (){
    local title="The Red Hat Enterprise Linux operating system must initiate a session lock for the screensaver
after a period of inactivity for graphical user interfaces."
    local requirement="idle-activation-enabled must be present and not set to false"

    local vuln_id='V-204402'
    local rule_id='SV-204402r505924_rule'
    local cci='CCI-000057'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep --directories=skip idle-activation-enabled /etc/dconf/db/local.d/*`
    current_status=$( [[ "$check_results" != *"idle-activation-enabled=true"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ "$check_results" != *"idle-activation-enabled=true"* ]] || [[ $force_flag == 'true' ]]; then
            touch "/etc/dconf/db/local.d/00-screensaver"
            set_config_value "/etc/dconf/db/local.d/00-screensaver"  "org/gnome/desktop/screensaver" "idle-activation-enabled" "true"
            dconf update
            remediation="Updated settings in /etc/dconf/db/local.d/00-screensaver"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep --directories=skip idle-activation-enabled /etc/dconf/db/local.d/*`
    final_status=$( [[ "$final_results" != *"idle-activation-enabled=true"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204403 (){
    local title="The Red Hat Enterprise Linux operating system must prevent a user from overriding the screensaver
idle-activation-enabled setting for the graphical user interface."
    local requirement="idle-activation-enabled must be locked"

    local vuln_id='V-204403'
    local rule_id='SV-204403r505924_rule'
    local cci='CCI-000057'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep --directories=skip idle-activation-enabled /etc/dconf/db/local.d/locks/*`
    current_status=$( [[ "$check_results" != *"idle-activation-enabled"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ "$check_results" != *"idle-activation-enabled"* ]] || [[ $force_flag == 'true' ]]; then
            touch "/etc/dconf/db/local.d/locks/session"

            tmpfile=$(mktemp)
            while read -r line
            do
                if ! [[ $line == *"idle-activation-enabled"* ]]; then
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/dconf/db/local.d/locks/session
            echo "/org/gnome/desktop/screensaver/idle-activation-enabled" >> "$tmpfile"
            mv "$tmpfile" "/etc/dconf/db/local.d/locks/session"
            dconf update
            remediation="Updated settings in /etc/dconf/db/local.d/locks/session"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep --directories=skip idle-activation-enabled /etc/dconf/db/local.d/locks/*`
    final_status=$( [[ "$final_results" != *"idle-activation-enabled"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204404 (){
    local title="The Red Hat Enterprise Linux operating system must initiate a session lock for graphical user
interfaces when the screensaver is activated."
    local requirement="idle-activation-enabled must be present and set to 5"

    local vuln_id='V-204404'
    local rule_id='SV-204404r505924_rule'
    local cci='CCI-000057'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep --directories=skip lock-delay /etc/dconf/db/local.d/*`
    current_status=$( [[ "$check_results" != *"lock-delay=uint32 5"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ "$check_results" != *"lock-delay=uint32 5"* ]] || [[ $force_flag == 'true' ]]; then
            touch "/etc/dconf/db/local.d/00-screensaver"
            set_config_value "/etc/dconf/db/local.d/00-screensaver"  "org/gnome/desktop/screensaver" "lock-delay" "uint32 5"
            dconf update
            remediation="Updated settings in /etc/dconf/db/local.d/00-screensaver"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep --directories=skip lock-delay /etc/dconf/db/local.d/*`
    final_status=$( [[ "$final_results" != *"lock-delay=uint32 5"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204405 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that /etc/pam.d/passwd
implements /etc/pam.d/system-auth when changing passwords."
    local requirement="system-auth must be configured for use"

    local vuln_id='V-204405'
    local rule_id='SV-204405r505924_rule'
    local cci='CCI-000192'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    local test_pattern=".*password.+substack.+system-auth.*"

    check_results=`cat /etc/pam.d/passwd | grep -i substack | grep -i system-auth | grep -ve "#.*password"`
    current_status=$( ! [[ "$check_results" =~ $test_pattern ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if ! [[ "$check_results" =~ $test_pattern ]] || [[ $force_flag == 'true' ]]; then
            tmpfile=$(mktemp)
            while read -r line
            do
                if ! [[ $line =~ $test_pattern ]]; then
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/pam.d/passwd
            echo "password  substack    system-auth" >> "$tmpfile"
            mv "$tmpfile" "/etc/pam.d/passwd"
            remediation="Updated settings in /etc/pam.d/passwd"
        else
            remediation="Not required"
        fi
    fi

    final_results=`cat /etc/pam.d/passwd | grep -i substack | grep -i system-auth | grep -ve "#.*password"`
    final_status=$( ! [[ "$final_results" =~ $test_pattern ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204406 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed
or new passwords are established, pwquality must be used."
    local requirement="system-auth must be configured to ensure password quality"

    local vuln_id='V-204406'
    local rule_id='SV-204406r505924_rule'
    local cci='CCI-000192'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`cat /etc/pam.d/system-auth | grep required | grep pam_pwquality | grep "retry=3" | grep -v "#password"`
    current_status=$( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] || [[ $force_flag == 'true' ]]; then
            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"password"* ]] && [[ $line == *"required"* ]] && [[ $line == *"pam_pwquality"* ]]; then
                    echo "password  required    pam_pwquality.so    retry=3"  >> "$tmpfile"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/pam.d/system-auth

            if [[ $( grep -i password "$tmpfile" | grep -i required | grep -i pam_pwquality | wc -c) -eq 0 ]]; then
                echo "password  required    pam_pwquality.so    retry=3"  >> "$tmpfile"
            fi

            mv "$tmpfile" "/etc/pam.d/system-auth"
            remediation="Updated settings in /etc/pam.d/system-auth"
        else
            remediation="Not required"
        fi
    fi

    final_results=`cat /etc/pam.d/system-auth | grep required | grep pam_pwquality | grep "retry=3" | grep -v "#password"`
    final_status=$( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204407 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed
or new passwords are established, the new password must contain at least one upper-case character."
    local requirement="the value ucredit = -1 must be in the pwquality.conf file"

    local vuln_id='V-204407'
    local rule_id='SV-204407r505924_rule'
    local cci='CCI-000192'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep -e "^ucredit = -1" /etc/security/pwquality.conf`
    current_status=$( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" | wc -c) -eq 0  ]] || [[ $force_flag == 'true' ]]; then
            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"ucredit"* ]]; then
                    echo "ucredit = -1" >> "$tmpfile"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/security/pwquality.conf

            if [[ $( grep -i ucredit "$tmpfile" | wc -c) -eq 0 ]]; then
                echo "ucredit = -1" >> "$tmpfile"
            fi

            mv "$tmpfile" "/etc/security/pwquality.conf"
            remediation="Updated settings in /etc/security/pwquality.conf"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep -e "^ucredit = -1" /etc/security/pwquality.conf`
    final_status=$( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204408 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed
or new passwords are established, the new password must contain at least one lower-case character."
    local requirement="the value lcredit = -1 must be in the pwquality.conf file"

    local vuln_id='V-204408'
    local rule_id='SV-204408r505924_rule'
    local cci='CCI-000193'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep -e "^lcredit = -1" /etc/security/pwquality.conf`
    current_status=$( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" | wc -c) -eq 0  ]] || [[ $force_flag == 'true' ]]; then
            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"lcredit"* ]]; then
                    echo "lcredit = -1" >> "$tmpfile"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/security/pwquality.conf

            if [[ $( grep -i lcredit "$tmpfile" | wc -c) -eq 0 ]]; then
                echo "lcredit = -1" >> "$tmpfile"
            fi

            mv "$tmpfile" "/etc/security/pwquality.conf"
            remediation="Updated settings in /etc/security/pwquality.conf"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep -e "^lcredit = -1" /etc/security/pwquality.conf`
    final_status=$( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204409 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed
or new passwords are assigned, the new password must contain at least one numeric character."
    local requirement="the value dcredit = -1 must be in the pwquality.conf file"

    local vuln_id='V-204409'
    local rule_id='SV-204409r505924_rule'
    local cci='CCI-000194'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep -e "^dcredit = -1" /etc/security/pwquality.conf`
    current_status=$( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" | wc -c) -eq 0  ]] || [[ $force_flag == 'true' ]]; then
            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"dcredit"* ]]; then
                    echo "dcredit = -1" >> "$tmpfile"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/security/pwquality.conf

            if [[ $( grep -i dcredit "$tmpfile" | wc -c) -eq 0 ]]; then
                echo "dcredit = -1" >> "$tmpfile"
            fi

            mv "$tmpfile" "/etc/security/pwquality.conf"
            remediation="Updated settings in /etc/security/pwquality.conf"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep -e "^dcredit = -1" /etc/security/pwquality.conf`
    final_status=$( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204410 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed
or new passwords are established, the new password must contain at least one special character."
    local requirement="the value ocredit = -1 must be in the pwquality.conf file"

    local vuln_id='V-204410'
    local rule_id='SV-204410r505924_rule'
    local cci='CCI-001619'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep -e "^ocredit = -1" /etc/security/pwquality.conf`
    current_status=$( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" | wc -c) -eq 0  ]] || [[ $force_flag == 'true' ]]; then
            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"ocredit"* ]]; then
                    echo "ocredit = -1" >> "$tmpfile"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/security/pwquality.conf

            if [[ $( grep -i ocredit "$tmpfile" | wc -c) -eq 0 ]]; then
                echo "ocredit = -1" >> "$tmpfile"
            fi

            mv "$tmpfile" "/etc/security/pwquality.conf"
            remediation="Updated settings in /etc/security/pwquality.conf"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep -e "^ocredit = -1" /etc/security/pwquality.conf`
    final_status=$( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204411 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed
a minimum of eight of the total number of characters must be changed."
    local requirement="the value difok = 8 must be in the pwquality.conf file"

    local vuln_id='V-204411'
    local rule_id='SV-204411r505924_rule'
    local cci='CCI-000195'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep -e "^difok = 8" /etc/security/pwquality.conf`
    current_status=$( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" | wc -c) -eq 0  ]] || [[ $force_flag == 'true' ]]; then
            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"difok"* ]]; then
                    echo "difok = 8" >> "$tmpfile"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/security/pwquality.conf

            if [[ $( grep -i difok "$tmpfile" | wc -c) -eq 0 ]]; then
                echo "difok = 8" >> "$tmpfile"
            fi

            mv "$tmpfile" "/etc/security/pwquality.conf"
            remediation="Updated settings in /etc/security/pwquality.conf"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep -e "^difok = 8" /etc/security/pwquality.conf`
    final_status=$( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204412 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed
a minimum of four character classes must be changed."
    local requirement="the value minclass = 4 must be in the pwquality.conf file"

    local vuln_id='V-204412'
    local rule_id='SV-204412r505924_rule'
    local cci='CCI-000195'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep -e "^minclass = 4" /etc/security/pwquality.conf`
    current_status=$( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" | wc -c) -eq 0  ]] || [[ $force_flag == 'true' ]]; then
            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"minclass"* ]]; then
                    echo "minclass = 4" >> "$tmpfile"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/security/pwquality.conf

            if [[ $( grep -i minclass "$tmpfile" | wc -c) -eq 0 ]]; then
                echo "minclass = 4" >> "$tmpfile"
            fi

            mv "$tmpfile" "/etc/security/pwquality.conf"
            remediation="Updated settings in /etc/security/pwquality.conf"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep -e "^minclass = 4" /etc/security/pwquality.conf`
    final_status=$( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204413 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed
the number of repeating consecutive characters must not be more than three characters."
    local requirement="the value maxrepeat = 3 must be in the pwquality.conf file"

    local vuln_id='V-204413'
    local rule_id='SV-204413r505924_rule'
    local cci='CCI-000195'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep -e "^maxrepeat = 3" /etc/security/pwquality.conf`
    current_status=$( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" | wc -c) -eq 0  ]] || [[ $force_flag == 'true' ]]; then
            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"maxrepeat"* ]]; then
                    echo "maxrepeat = 3" >> "$tmpfile"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/security/pwquality.conf

            if [[ $( grep -i maxrepeat "$tmpfile" | wc -c) -eq 0 ]]; then
                echo "maxrepeat = 3" >> "$tmpfile"
            fi

            mv "$tmpfile" "/etc/security/pwquality.conf"
            remediation="Updated settings in /etc/security/pwquality.conf"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep -e "^maxrepeat = 3" /etc/security/pwquality.conf`
    final_status=$( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204414 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed
the number of repeating characters of the same character class must not be more than four
characters."
    local requirement="the value maxclassrepeat = 4 must be in the pwquality.conf file"

    local vuln_id='V-204414'
    local rule_id='SV-204414r505924_rule'
    local cci='CCI-000195'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep -e "^maxclassrepeat = 4" /etc/security/pwquality.conf`
    current_status=$( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" | wc -c) -eq 0  ]] || [[ $force_flag == 'true' ]]; then
            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"maxclassrepeat"* ]]; then
                    echo "maxclassrepeat = 4" >> "$tmpfile"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/security/pwquality.conf

            if [[ $( grep -i maxclassrepeat "$tmpfile" | wc -c) -eq 0 ]]; then
                echo "maxclassrepeat = 4" >> "$tmpfile"
            fi

            mv "$tmpfile" "/etc/security/pwquality.conf"
            remediation="Updated settings in /etc/security/pwquality.conf"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep -e "^maxclassrepeat = 4" /etc/security/pwquality.conf`
    final_status=$( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204415 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that the PAM system service is
configured to store only encrypted representations of passwords."
    local requirement="the system is configured to create SHA512 hashed passwords"

    local vuln_id='V-204415'
    local rule_id='SV-204415r505924_rule'
    local cci='CCI-000196'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep password /etc/pam.d/system-auth /etc/pam.d/password-auth | grep pam_unix.so`
    current_status=$( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] || [[ $force_flag == 'true' ]]; then
            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"password"* ]] && [[ $line == *"sufficient"* ]] && [[ $line == *"pam_unix.so"* ]]; then
                    echo "password  sufficient  pam_unix.so sha512 shadow try_first_pass use_authtok"  >> "$tmpfile"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/pam.d/system-auth

            if [[ $( grep password /etc/pam.d/system-auth | grep pam_unix.so | wc -c) -eq 0 ]]; then
                echo "password  sufficient  pam_unix.so sha512 shadow try_first_pass use_authtok"  >> "$tmpfile"
            fi

            mv "$tmpfile" "/etc/pam.d/system-auth"

            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"password"* ]] && [[ $line == *"sufficient"* ]] && [[ $line == *"pam_unix.so"* ]]; then
                    echo "password  sufficient  pam_unix.so sha512 shadow try_first_pass use_authtok"  >> "$tmpfile"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/pam.d/password-auth

            if [[ $( grep password /etc/pam.d/password-auth | grep pam_unix.so | wc -c) -eq 0 ]]; then
                echo "password  sufficient  pam_unix.so sha512 shadow try_first_pass use_authtok"  >> "$tmpfile"
            fi

            mv "$tmpfile" "/etc/pam.d/password-auth"

            remediation="Updated settings in:
    /etc/pam.d/system-auth
    /etc/pam.d/password-auth"

        else
            remediation="Not required"
        fi
    fi

    final_results=`grep password /etc/pam.d/system-auth /etc/pam.d/password-auth | grep pam_unix.so`
    final_status=$( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204416 (){
    local title="The Red Hat Enterprise Linux operating system must be configured to use the shadow file to store
only encrypted representations of passwords."
    local requirement="the system is configured to create SHA512 hashed passwords"

    local vuln_id='V-204416'
    local rule_id='SV-204416r505924_rule'
    local cci='CCI-000196'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep -i encrypt_method /etc/login.defs`
    current_status=$( ( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] || [[ "$check_results" != *"512"* ]] ) && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if
            [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] ||
            [[ "$check_results" != *"512"* ]] ||
            [[ $force_flag == 'true' ]];
        then
            method_present=""
            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"ENCRYPT_METHOD"* ]]; then
                    echo "ENCRYPT_METHOD SHA512"  >> "$tmpfile"
                    method_present="1"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/login.defs
            if [ -z $method_present ]; then
                echo "ENCRYPT_METHOD SHA512"  >> "$tmpfile"
            fi
            mv "$tmpfile" "/etc/login.defs"
            remediation="Updated settings in /etc/login.defs"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep -i encrypt_method /etc/login.defs`
    final_status=$( ( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] || [[ "$final_results" != *"512"* ]] ) && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204417 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that user and group account
administration utilities are configured to store only encrypted representations of passwords."
    local requirement="crypt_style must be set to sha512"

    local vuln_id='V-204417'
    local rule_id='SV-204417r505924_rule'
    local cci='CCI-000196'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep -i crypt_style /etc/libuser.conf | grep -i sha512`
    current_status=$( [[ "$check_results" != *"crypt_style = sha512"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ "$check_results" != *"crypt_style = sha512"* ]] || [[ $force_flag == 'true' ]]; then
            touch "/etc/libuser.conf"
            set_config_value "/etc/libuser.conf"  "defaults" "crypt_style " " sha512"
            remediation="Updated settings in /etc/libuser.conf"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep -i crypt_style /etc/libuser.conf | grep -i sha512`
    final_status=$( [[ "$final_results" != *"crypt_style = sha512"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204418 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that passwords for new users
are restricted to a 24 hours/1 day minimum lifetime."
    local requirement="the system is configured to prevent passwords from changing more than once a day"

    local vuln_id='V-204418'
    local rule_id='SV-204418r505924_rule'
    local cci='CCI-000198'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep -e "^PASS_MIN_DAYS.*" /etc/login.defs`
    current_status=$( ( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] || [[ "$check_results" != *"PASS_MIN_DAYS  1"* ]] ) && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if
            [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] ||
            [[ "$check_results" != *"PASS_MIN_DAYS 1"* ]] ||
            [[ $force_flag == 'true' ]];
        then
            val_present=""
            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == "PASS_MIN_DAYS"* ]]; then
                    echo "PASS_MIN_DAYS 1"  >> "$tmpfile"
                    val_present="1"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/login.defs
            if [ -z $val_present ]; then
                echo "PASS_MIN_DAYS 1"  >> "$tmpfile"
            fi
            mv "$tmpfile" "/etc/login.defs"
            remediation="Updated settings in /etc/login.defs"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep -e "^PASS_MIN_DAYS.*" /etc/login.defs`
    final_status=$( ( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] || [[ "$final_results" != *"PASS_MIN_DAYS  1"* ]] ) && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204419 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that passwords are
restricted to a 24 hours/1 day minimum lifetime."
    local requirement=" the minimum time period between password changes for each user account is one day
or greater."

    local vuln_id='V-204419'
    local rule_id='SV-204419r505924_rule'
    local cci='CCI-000198'
    local severity='CAT II'

    local current_status="NotReviewed"
    local remediation="No Automations available"
    local check_results=`awk -F: '$4 < 1 {print $1 " " $4}' /etc/shadow`
    local final_results='This requirement can not be auotmatically checked or updated'
    local final_status="NotReviewed"
    local comments=""
    local ckl_verbiage=""

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204420 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that passwords for new
users are restricted to a 60-day maximum lifetime."
    local requirement=" the operating system enforces a 60-day maximum password lifetime restriction for
new user accounts"

    local vuln_id='V-204420'
    local rule_id='SV-204420r505924_rule'
    local cci='CCI-000199'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep -e "^PASS_MAX_DAYS.*" /etc/login.defs`
    current_status=$( ( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] || [[ "$check_results" != *"PASS_MAX_DAYS 60"* ]] ) && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if
            [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] ||
            [[ "$check_results" != *"PASS_MAX_DAYS 60"* ]] ||
            [[ $force_flag == 'true' ]];
        then
            val_present=""
            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == "PASS_MAX_DAYS"* ]]; then
                    echo "PASS_MAX_DAYS 60"  >> "$tmpfile"
                    val_present="1"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/login.defs
            if [ -z $val_present ]; then
                echo "PASS_MAX_DAYS 60"  >> "$tmpfile"
            fi
            mv "$tmpfile" "/etc/login.defs"
            remediation="Updated settings in /etc/login.defs"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep -e "^PASS_MAX_DAYS.*" /etc/login.defs`
    final_status=$( ( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] || [[ "$final_results" != *"PASS_MAX_DAYS 60"* ]] ) && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204421 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that existing passwords
are restricted to a 60-day maximum lifetime."
    local requirement="the maximum time period for existing passwords is restricted to 60 days"

    local vuln_id='V-204421'
    local rule_id='SV-204421r505924_rule'
    local cci='CCI-000199'
    local severity='CAT II'

    local current_status="NotReviewed"
    local remediation="No Automations available"
    local check_results=`awk -F: '$4 < 1 {print $1 " " $4}' /etc/shadow`
    local final_results='This requirement can not be auotmatically checked or updated'
    local final_status="NotReviewed"
    local comments=""
    local ckl_verbiage=""

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204422 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that passwords are
prohibited from reuse for a minimum of five generations."
    local requirement="the operating system prohibits password reuse for a minimum of five generations."

    local vuln_id='V-204422'
    local rule_id='SV-204422r505924_rule'
    local cci='CCI-000200'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep password /etc/pam.d/system-auth /etc/pam.d/password-auth | grep pam_pwhistory.so`
    current_status=$( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] || [[ $force_flag == 'true' ]]; then
            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"password"* ]] && [[ $line == *"requisite"* ]] && [[ $line == *"pam_pwhistory.so"* ]]; then
                    echo "password    requisite    pam_pwhistory.so use_authtok remember=5 retry=3"  >> "$tmpfile"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/pam.d/system-auth

            if [[ $( grep password "$tmpfile" | grep pam_pwhistory.so | wc -c) -eq 0 ]]; then
                echo "password    requisite    pam_pwhistory.so use_authtok remember=5 retry=3"  >> "$tmpfile"
            fi

            mv "$tmpfile" "/etc/pam.d/system-auth"

            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"password"* ]] && [[ $line == *"requisite"* ]] && [[ $line == *"pam_pwhistory.so"* ]]; then
                    echo "password    requisite    pam_pwhistory.so use_authtok remember=5 retry=3"  >> "$tmpfile"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/pam.d/password-auth

            if [[ $( grep password "$tmpfile" | grep pam_pwhistory.so | wc -c) -eq 0 ]]; then
                echo "password    requisite    pam_pwhistory.so use_authtok remember=5 retry=3"  >> "$tmpfile"
            fi

            mv "$tmpfile" "/etc/pam.d/password-auth"

            remediation="Updated settings in:
    /etc/pam.d/system-auth
    /etc/pam.d/password-auth"

        else
            remediation="Not required"
        fi
    fi

    final_results=`grep password /etc/pam.d/system-auth /etc/pam.d/password-auth | grep pam_pwhistory.so`
    final_status=$( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204423 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that passwords are a
minimum of 15 characters in length."
    local requirement="the operating system enforces a minimum 15-character password length"

    local vuln_id='V-204423'
    local rule_id='SV-204423r505924_rule'
    local cci='CCI-000205'
    local severity='CAT II'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep -e "^minlen = 15" /etc/security/pwquality.conf`
    current_status=$( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" | wc -c) -eq 0  ]] || [[ $force_flag == 'true' ]]; then
            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"minlen"* ]]; then
                    echo "minlen = 15" >> "$tmpfile"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/security/pwquality.conf

            if [[ $( grep -i minlen "$tmpfile" | wc -c) -eq 0 ]]; then
                echo "minlen = 15" >> "$tmpfile"
            fi

            mv "$tmpfile" "/etc/security/pwquality.conf"
            remediation="Updated settings in /etc/security/pwquality.conf"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep -e "^minlen = 15" /etc/security/pwquality.conf`
    final_status=$( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204424 (){
    local title="The Red Hat Enterprise Linux operating system must not have accounts configured with blank
or null passwords"
    local requirement="verify that null passwords cannot be used"

    local vuln_id='V-204424'
    local rule_id='SV-204424r505924_rule'
    local cci='CCI-000366'
    local severity='CAT I'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep nullok /etc/pam.d/system-auth /etc/pam.d/password-auth`
    current_status=$( [[ $( echo -n "$check_results" | wc -c) -ne 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" | wc -c) -ne 0 ]] || [[ $force_flag == 'true' ]]; then

            sed --follow-symlinks -i 's/\<nullok\>//g' /etc/pam.d/system-auth
            sed --follow-symlinks -i 's/\<nullok\>//g' /etc/pam.d/password-auth

            remediation="Updated settings in:
    /etc/pam.d/system-auth
    /etc/pam.d/password-auth"

        else
            remediation="Not required"
        fi
    fi

    final_results=`grep nullok /etc/pam.d/system-auth /etc/pam.d/password-auth`
    final_status=$( [[ $( echo -n "$final_results" | wc -c) -ne 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204425 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon
does not allow authentication using an empty password."
    local requirement="The ssh daemon must be set to prevent empty passwords."
    local vuln_id='V-204425'
    local rule_id='SV-204425r505924_rule'
    local cci='CCI-000766'
    local severity='CAT I'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results="$(grep -Ei "^PermitEmptyPasswords[[:space:]]+no" /etc/ssh/sshd_config)"
    current_status=$( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if
            [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] ||
            [[ $force_flag == 'true' ]];
        then

            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"PermitEmptyPasswords"* ]]; then
                    echo "PermitEmptyPasswords no" >> "$tmpfile"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/ssh/sshd_config

            if [[ $(grep -Ei "^PermitEmptyPasswords[[:space:]]+No" "$tmpfile" | wc -c)  -eq 0 ]]; then
                echo "PermitEmptyPasswords no" >> "$tmpfile"
            fi

            mv "$tmpfile" "/etc/ssh/sshd_config"
            remediation="Updated settings in /etc/ssh/sshd_config"
         else
            remediation="Not required"
        fi
    fi

    final_results="$(grep -Ei "^PermitEmptyPasswords[[:space:]]+no" /etc/ssh/sshd_config)"
    final_status=$( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204432 (){
    local title="The Red Hat Enterprise Linux operating system must not allow an unattended or automatic 
logon to the system via a graphical user interface."
    local requirement="AutomaticLoginEnable must be present and not set to false"
    local vuln_id='V-204432'
    local rule_id='SV-204432r505924_rule'
    local cci='CCI-000366'
    local severity='CAT I'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep -i automaticloginenable /etc/gdm/custom.conf`
    current_status=$( [[ "$check_results" != *"AutomaticLoginEnable=false"* ]] && echo "Open" || echo "NotAFinding")

    #Fix requirement if needed
    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ "$check_results" != *"AutomaticLoginEnable=false"* ]] || [[ $force_flag == 'true' ]]; then
            touch "/etc/gdm/custom.conf"
            set_config_value "/etc/gdm/custom.conf"  "daemon" "AutomaticLoginEnable" "false"
            
            remediation="Updated settings in /etc/gdm/custom.conf"
        else
            remediation="Not required"
        fi
    fi

    #check settings again after fix
    final_results=`grep -i automaticloginenable /etc/gdm/custom.conf`
    final_status=$( [[ "$final_results" != *"AutomaticLoginEnable=false"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204433 (){
    local title="The Red Hat Enterprise Linux operating system must not allow an unrestricted logon to the system."
    local requirement="TimedLoginEnable must be present and not set to false"
    local vuln_id='V-204433'
    local rule_id='SV-204433r505924_rule'
    local cci='CCI-000366'
    local severity='CAT I'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep -i TimedLoginEnable /etc/gdm/custom.conf`
    current_status=$( [[ "$check_results" != *"TimedLoginEnable=false"* ]] && echo "Open" || echo "NotAFinding")

    #Fix requirement if needed
    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ "$check_results" != *"TimedLoginEnable=false"* ]] || [[ $force_flag == 'true' ]]; then
            touch "/etc/gdm/custom.conf"
            set_config_value "/etc/gdm/custom.conf"  "daemon" "TimedLoginEnable" "false"
            
            remediation="Updated settings in /etc/gdm/custom.conf"
        else
            remediation="Not required"
        fi
    fi

    #check settings again after fix
    final_results=`grep -i TimedLoginEnable /etc/gdm/custom.conf`
    final_status=$( [[ "$final_results" != *"TimedLoginEnable=false"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204442 (){
    local title="The Red Hat Enterprise Linux operating system must not have the rsh-server package installed."
    local requirement="The rsh-server package must not be installed"
    local vuln_id='V-204442'
    local rule_id='SV-204442r505924_rule'
    local cci='CCI-000381'
    local severity='CAT I'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`yum list installed rsh-server 2>&1 | grep -i "No matching Packages" | wc -l`
    current_status=$( [[ $( echo -n "$check_results" ) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    #Fix requirement if needed
    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" ) -eq 0 ]] || [[ $force_flag == 'true' ]]; then
            yum remove rsh-server
            
            remediation="Removed rsh-server"
        else
            remediation="Not required"
        fi
    fi

    #check settings again after fix
    final_results=`yum list installed rsh-server 2>&1 | grep -i "No matching Packages" | wc -l`
    final_status=$( [[ $( echo -n "$final_results" ) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204443 (){
    local title="The Red Hat Enterprise Linux operating system must not have the ypserv package installed."
    local requirement="The ypserv package must not be installed"
    local vuln_id='V-204443'
    local rule_id='SV-204443r505924_rule'
    local cci='CCI-000381'
    local severity='CAT I'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`yum list installed ypserv 2>&1 | grep -i "No matching Packages" | wc -l`
    current_status=$( [[ $( echo -n "$check_results" ) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    #Fix requirement if needed
    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" ) -eq 0 ]] || [[ $force_flag == 'true' ]]; then
            yum remove ypserv
            
            remediation="Removed ypserv"
        else
            remediation="Not required"
        fi
    fi

    #check settings again after fix
    final_results=`yum list installed ypserv 2>&1 | grep -i "No matching Packages" | wc -l`
    final_status=$( [[ $( echo -n "$final_results" ) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204447 (){
    local title="The Red Hat Enterprise Linux operating system must prevent the installation of software, patches, 
service packs, device drivers, or operating system components from a repository without 
verification they have been digitally signed using a certificate that is issued by a Certificate 
Authority (CA) that is recognized and approved by the organization."
    local requirement="the value gpgcheck = 1 must be in  /etc/yum.conf"

    local vuln_id='V-204447'
    local rule_id='SV-204447r505924_rule'
    local cci='CCI-001749'
    local severity='CAT I'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep -e "^gpgcheck=1" /etc/yum.conf`
    current_status=$( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] || [[ $force_flag == 'true' ]]; then
            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"gpgcheck"* ]]; then
                    echo "gpgcheck=1" >> "$tmpfile"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/yum.conf

            if [[ $( grep -i gpgcheck "$tmpfile" | wc -c) -eq 0 ]]; then
                echo "gpgcheck=1" >> "$tmpfile"
            fi

            mv "$tmpfile" "/etc/yum.conf"
            remediation="Updated settings in /etc/yum.conf"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep -e "^gpgcheck=1" /etc/yum.conf`
    final_status=$( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204448 (){
    local title="The Red Hat Enterprise Linux operating system must prevent the installation of software, 
patches, service packs, device drivers, or operating system components of local packages without 
verification they have been digitally signed using a certificate that is issued by a Certificate 
Authority (CA) that is recognized and approved by the organization."
    local requirement="the value localpkg_gpgcheck=1 must be in  /etc/yum.conf"

    local vuln_id='V-204448'
    local rule_id='SV-204448r505924_rule	'
    local cci='CCI-001749'
    local severity='CAT I'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep -e "^localpkg_gpgcheck=1" /etc/yum.conf`
    current_status=$( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] || [[ $force_flag == 'true' ]]; then
            tmpfile=$(mktemp)
            while read -r line
            do
                if [[ $line == *"localpkg_gpgcheck"* ]]; then
                    echo "localpkg_gpgcheck=1" >> "$tmpfile"
                else
                    echo "$line" >> "$tmpfile"
                fi
            done < /etc/yum.conf

            if [[ $( grep -i localpkg_gpgcheck "$tmpfile" | wc -c) -eq 0 ]]; then
                echo "" >> "$tmpfile"
                echo "localpkg_gpgcheck=1" >> "$tmpfile"
            fi

            mv "$tmpfile" "/etc/yum.conf"
            remediation="Updated settings in /etc/yum.conf"
        else
            remediation="Not required"
        fi
    fi

    final_results=`grep -e "^localpkg_gpgcheck=1" /etc/yum.conf`
    final_status=$( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204455 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that the x86 
Ctrl-Alt-Delete key sequence is disabled on the command line."
    local requirement="the ctrl-alt-del.target must be masked"
    local vuln_id='V-204455'
    local rule_id='SV-204455r505924_rule'
    local cci='CCI-000366'
    local severity='CAT I'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`echo $(( $(systemctl status ctrl-alt-del.target | grep "Loaded: masked" | wc -l) + $(systemctl status ctrl-alt-del.target | grep "Active: inactive" | wc -l)  ))`
    current_status=$( [[ $( echo -n "$check_results" ) -ne 2 ]] && echo "Open" || echo "NotAFinding")

    #Fix requirement if needed
    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" ) -ne 2 ]] || [[ $force_flag == 'true' ]]; then
            systemctl mask ctrl-alt-del.target
            
            remediation="Masked ctrl-alt-del"
        else
            remediation="Not required"
        fi
    fi

    #check settings again after fix
    final_results=`echo $(( $(systemctl status ctrl-alt-del.target | grep "Loaded: masked" | wc -l) + $(systemctl status ctrl-alt-del.target | grep "Active: inactive" | wc -l)  ))`
    final_status=$( [[ $( echo -n "$final_results" ) -ne 2 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
} 

function _V204456 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that the x86 
Ctrl-Alt-Delete key sequence is disabled in the Graphical User Interface."
    local requirement="logout must be set to '' in /etc/dconf/db/local.d/00-disable-CAD "
    local vuln_id='V-204456'
    local rule_id='SV-204456r505924_rule'
    local cci='CCI-000366'
    local severity='CAT I'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`grep --directories=skip logout  /etc/dconf/db/local.d/*`
    current_status=$( [[ "$check_results" != *"logout=''"* ]] && echo "Open" || echo "NotAFinding")

    #Fix requirement if needed
    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ "$check_results" != *"logout=''"* ]] || [[ $force_flag == 'true' ]]; then
            touch /etc/dconf/db/local.d/00-disable-CAD 
            set_config_value "/etc/dconf/db/local.d/00-disable-CAD"  "org/gnome/settings-daemon/plugins/media-keys" "logout" "''"
            
            remediation="Updated settings in /etc/dconf/db/local.d/00-disable-CAD"
        else
            remediation="Not required"
        fi
    fi

    #check settings again after fix
    final_results=`grep --directories=skip logout  /etc/dconf/db/local.d/*`
    final_status=$( [[ "$final_results" != *"logout=''"* ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204458 (){
    local title="The Red Hat Enterprise Linux operating system must be a vendor supported release."
    local requirement="Release must be supported "
    local vuln_id='V-204458'
    local rule_id='SV-204458r505924_rule'
    local cci='CCI-000366'
    local severity='CAT I'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    
    if ([[ `cat /etc/redhat-release | grep -oP "([0-9]\.[0-9])"` == "7.6" ]]  && [[ $(date +%s) -lt $(date --date='October 31 2020' +%s) ]]) ||
([[ `cat /etc/redhat-release | grep -oP "([0-9]\.[0-9])"` == "7.7" ]]  && [[ $(date +%s) -lt $(date --date='August 31 2021' +%s) ]]) ||
([[ `cat /etc/redhat-release | grep -oP "([0-9]\.[0-9])"` == "7.8" ]]  && [[ $(date +%s) -lt $(date --date='October 31 2020' +%s) ]]) ||
([[ `cat /etc/redhat-release | grep -oP "([0-9]\.[0-9])"` == "7.9" ]]  && [[ $(date +%s) -lt $(date --date='April 30 2021' +%s) ]]); then
        check_results="Release is supported"
        current_status="NotAFinding"
        final_results="Release is supported"
        final_status="NotAFinding"
        remediation="Not Needed"
    else
        check_results="Release is not supported"
        current_status_status="Open"
        final_results="Release is not supported"
        final_status="Open"
        remediation="Upgrade to supported release"
    fi

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204462 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that the root account 
must be the only account having unrestricted access to the system."
    local requirement="Root must be the only account with unrestricted access"
    local vuln_id='V-204462'
    local rule_id='SV-204462r505924_rule'
    local cci='CCI-000366'
    local severity='CAT I'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    
    if [[ `awk -F: '$3 == 0 {print $1}' /etc/passwd | grep -v root | wc -l` -eq 0 ]]; then
        check_results="Root is the only unrestricted account on the system"
        current_status="NotAFinding"
        final_results="Root is the only unrestricted account on the system"
        final_status="NotAFinding"
        remediation="Not Needed"
    else
        check_results="Root is not the only unrestricted account on the system"
        current_status_status="Open"
        final_results="Root is not the only unrestricted account on the system"
        final_status="Open"
        remediation="Remove unrestricted access from non-root accounts"
    fi

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}


function _V204497 (){
    local title="The Red Hat Enterprise Linux operating system must implement NIST FIPS-validated cryptography 
for the following: to provision digital signatures, to generate cryptographic hashes, and to 
protect data requiring data-at-rest protections in accordance with applicable federal laws, 
Executive Orders, directives, policies, regulations, and standards."
    local requirement="FIPS must be installed and enabled"
    local vuln_id='V-204497'
    local rule_id='SV-204497r505924_rule'
    local cci='CCI-001199'
    local severity='CAT I'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""
    
    if [[ `sudo yum list installed dracut-fips 2>&1 | grep -i "No matching Packages" | wc -l` -ne 0 ]]  ||
[[ `sudo grep fips /boot/grub2/grub.cfg | wc -l` -ne 1 ]] ||
[[ `sudo cat /proc/sys/crypto/fips_enabled` -ne 1 ]] || 
[[ `sudo  ls -l /etc/system-fips 2>&1 | grep -i "no such file" | wc -l` -eq 1 ]]; then
        
        check_results="FIPS is not supported"
        current_status_status="Open"
        final_results="FIPS is not supported"
        final_status="Open"
        remediation="Install and utilize FIPS"
    else
        check_results="FIPS is supported"
        current_status="NotAFinding"
        final_results="FIPS is supported"
        final_status="NotAFinding"
        remediation="Not Needed"
    fi

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204502 (){
    local title="The Red Hat Enterprise Linux operating system must not have the telnet-server package installed."
    local requirement="The telnet-server package must not be installed"
    local vuln_id='V-204502'
    local rule_id='SV-204502r505924_rule'
    local cci='CCI-000381'
    local severity='CAT I'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`yum list installed telnet-server 2>&1 | grep -i "No matching Packages" | wc -l`
    current_status=$( [[ $( echo -n "$check_results" ) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    #Fix requirement if needed
    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if [[ $( echo -n "$check_results" ) -eq 0 ]] || [[ $force_flag == 'true' ]]; then
            yum remove telnet-server
            
            remediation="Removed telnet-server"
        else
            remediation="Not required"
        fi
    fi

    #check settings again after fix
    final_results=`yum list installed telnet-server 2>&1 | grep -i "No matching Packages" | wc -l`
    final_status=$( [[ $( echo -n "$final_results" ) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204594 (){
    local title="The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon 
is configured to only use the SSHv2 protocol."
    local requirement="The ssh daemon must be set to only allow SSHv2 connections"
    local vuln_id='V-204594'
    local rule_id='SV-204594r505924_rule'
    local cci='CCI-000197'
    local severity='CAT I'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""



    if [[ `cat /etc/redhat-release | grep -oP "[0-9]\.[0-9]" | cut -d'.' -f2` -le 4 ]]; then

        check_results="$(grep -Ei "^Protocol[[:space:]]+2" /etc/ssh/sshd_config)"
        current_status=$( [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

        if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
            if
                [[ $( echo -n "$check_results" | wc -c) -eq 0 ]] ||
                [[ $force_flag == 'true' ]];
            then

                tmpfile=$(mktemp)
                while read -r line
                do
                    if [[ $line == *"Protocol"* ]]; then
                        echo "Protocol 2" >> "$tmpfile"
                    else
                        echo "$line" >> "$tmpfile"
                    fi
                done < /etc/ssh/sshd_config

                if [[ $(grep -Ei "^Protocol[[:space:]]+2" "$tmpfile" | wc -c)  -eq 0 ]]; then
                    echo "Protocol 2" >> "$tmpfile"
                fi

                mv "$tmpfile" "/etc/ssh/sshd_config"
                remediation="Updated settings in /etc/ssh/sshd_config"
             else
                remediation="Not required"
            fi
        fi

        final_results="$(grep -Ei "^Protocol[[:space:]]+2" /etc/ssh/sshd_config)"
        final_status=$( [[ $( echo -n "$final_results" | wc -c) -eq 0 ]] && echo "Open" || echo "NotAFinding")

    else
        check_results="Requirement only applies to releases below 7.4"
        current_status="Not_Applicable"
        final_results="Requirement only applies to releases below 7.4"
        final_status="Not_Applicable"
        remediation="Not Needed"
    fi


    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204606 (){
    local title="The Red Hat Enterprise Linux operating system must not contain .shosts files."
    local requirement="There are no .shosts files on the system."
    local vuln_id='V-204606'
    local rule_id='SV-204606r505924_rule'
    local cci='CCI-000366'
    local severity='CAT I'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`find / -name '*.shosts' | wc -l`
    current_status=$( [[ $( echo -n "$check_results" ) -gt 0 ]] && echo "Open" || echo "NotAFinding")
    
    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if
            [[ $( echo -n "$check_results" ) -gt 0 ]] ||
            [[ $force_flag == 'true' ]];
        then
            find / -name '*.shosts' -delete
            
            remediation="Removed .shosts files"
         else
            remediation="Not required"
        fi
    fi

    final_results=`find / -name '*.shosts' | wc -l`
    final_status=$( [[ $( echo -n "$final_results" | wc -l) -gt 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}

function _V204607 (){
    local title="The Red Hat Enterprise Linux operating system must not contain shosts.equiv files."
    local requirement="There are no shosts.equiv files on the system."
    local vuln_id='V-204607'
    local rule_id='SV-204607r505924_rule'
    local cci='CCI-000366'
    local severity='CAT I'

    local current_status=""
    local remediation=""
    local check_results=""
    local final_results=""
    local final_status=""
    local comments=""
    local ckl_verbiage=""

    check_results=`find / -name '*shosts.equiv' | wc -l`
    current_status=$( [[ $( echo -n "$check_results" ) -gt 0 ]] && echo "Open" || echo "NotAFinding")
    
    if ! [ -z $fix_flag ] && [ $fix_flag == "true" ]; then
        if
            [[ $( echo -n "$check_results" ) -gt 0 ]] ||
            [[ $force_flag == 'true' ]];
        then
            find / -name '*shosts.equiv' -delete
            
            remediation="Removed .shosts files"
         else
            remediation="Not required"
        fi
    fi

    final_results=`find / -name '*shosts.equiv' | wc -l`
    final_status=$( [[ $( echo -n "$final_results" | wc -l) -gt 0 ]] && echo "Open" || echo "NotAFinding")

    if ! [ -z $ckl_file ]; then
        comments="CKL updated via $(basename $0) by $( who am i | awk '{print $1}' ) - $( date )"
        ckl_verbiage="Updating CKL File: $ckl_file
    Status   - $final_status
    Comments - $comments
    Details  - $final_results
"
        python -c "$_update_ckl" --ckl "$ckl_file" --rule "$rule_id" --status "$final_status" --comments "$comments" --details "$final_results"
    fi

    eval "cat <<EOF
$_template
EOF
"
}


















#-------------------------------------------------------------------------------
# Main Loop
#-------------------------------------------------------------------------------
clear;
fix_flag=''
force_flag=''
ckl_file=''
while getopts 'efc:' flag; do
      case "${flag}" in
            c) ckl_file=${OPTARG} ;;
            e) fix_flag='true' ;;
            f) force_flag='true' ;;
            *)
                print_usage
                exit 1
                ;;
      esac
done

IFS=$'\n'
index=0
for f in $(declare -F); do
    index=$((index + 1))
	if [[ ${f:11:2} == "_V" ]]; then
		${f:11} $index
	fi
done
