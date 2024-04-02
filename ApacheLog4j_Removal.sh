#!/bin/bash
#Apache Log4j Removal"
DOWNLOAD_FOLDER="/mnt/c/Users/rmodepu/Downloads"

echo "Get the latest file in the download folder:"
find "$DOWNLOAD_FOLDER" -type f -newermt "$(date +%Y-%m-%d)" ! -newermt "$(date -d "+1 day" +%Y-%m-%d)" | grep -v "vulns.csv"

read -p "Enter the latest file (including any spaces or special characters): " file

file_path="$DOWNLOAD_FOLDER/$file"

# Remove single quotes from file_path
file_path="${file_path//\'/}"

if [ -f "$file_path" ]; then
    echo "List/Count the file content:" "$(awk '{ print }' "$file_path" | wc -l)"
else
    echo "File not found: $file_path"
fi

echo "================================================"

read -p "Remediation Apache Log4j ..y/n:" Action

if [ "$Action" == "y" ]; then

    Apache_Log4j_sort_function() {
        Log4j="$HOME/log4j/inventory_log4j"
        Paths="$HOME/log4j/vfile"
        Var_Total_Hosts="$HOME/log4j/inventory_log4j1"
        Var_Reachable_hosts="$HOME/log4j/inventory_online"
        Var_Unreachable_hosts="$HOME/log4j/inventory_offline"
        PluginOutput="<plugin_output>"
        key_word="log4j"
        key_word_plugin_name="Apache Log4j"
        LOG_FILE="/var/tmp/log4j"
        VULNERABLE_FILE="/var/tmp/vfile1"
        Unreachable="/mnt/c/Users/rmodepu/Desktop/CSVfile/Log4j/unreachable-$(date +"%d.%m.%Y").csv"
        TAR="/mnt/c/Users/rmodepu/Desktop/CSVfile/log4j/log4j_$(date +"%d-%m-%Y").TAR.csv"

        log4j_Paths=$(while IFS=, read -r col1 col2 col3 col4 col5 col6; do
            echo "$col1 $col2 $col3 $col4 $col5 $col6"
        done < "$file_path" \
            | awk -F"," '{ print $1 }' \
            | awk '!visited[$0]++' \
            | sed 's/\\\\\\//g' \
            | grep -i "patching_third_party" \
            | egrep "$key_word" \
            | awk -F"Path:" '{ print $2}' \
            | sed 's/\\//g' \
            | sed 's/^.//g' \
            | cut -d" " -f 1  | awk '!visited[$0]++')

        log4j_Hosts=$(while IFS=, read -r col1 col2 col3 col4 col5 col6; do \
            echo "$col1" "$col3" "$col4" "$col5" "$col6"; done < "$file_path" \
            | awk -F"," '{ print $1 }' | awk '!visited[$0]++' | sed 's/\\\\\\//g' \
            | grep -i "patching_third_party" | egrep "$key_word" | sed 's/\\//g' \
            | awk -F" " '{ print $2}' | awk '!visited[$0]++')

        if [[ "$PluginOutput" == *"<plugin_output>"* ]]; then
            echo "$log4j_Paths" > "$Paths"
            echo "$log4j_Hosts" > "$Log4j"

            echo -e "Paths are Below:\n$(grep -i "" "$Paths")"
            echo "TotalPathCount:" $(grep -c "" "$Paths")
            echo "TotalHostCount:" $(grep -c "" "$Log4j")
        else
            echo "Segregation Failed"
        fi
    }

    reachable_unreachable_machines_segregation() {
        echo "+++++++++++++++++++++++++++++++++++++++++++"
        echo -e "\e[0;31m *****Remediation initialized*****\e[0m"
        read -p "Enter y/n to Sort Reachable/Unreachable Hosts: " Action
        echo

        if [ "${Action}" == "y" ]; then
            echo -e "\e[0;31m***Please Wait for a couple of minutes to sort***.........\e[0m"
            ansible all -i "$Log4j" -a "id" -o > "$Var_Total_Hosts"
            grep -i "" "$Var_Total_Hosts" | grep -i CHANGED | awk -F "|" '{ print $1 }' \
            | egrep -wv "ECDSA|WARNING|host"  > "$Var_Reachable_hosts"

            grep -i "" "$Var_Total_Hosts" | grep -i UNREACHABLE \
            | awk -F "|" '{ print $1 }' > "$Var_Unreachable_hosts"

        else
            exit
        fi

        if [ -f "$inventory_file" ]; then
            echo "update starts using Ansible"
        else
            echo "file does not exist"
        fi

        echo -e "Reachable Machines counts: $(grep -c "" "$Var_Reachable_hosts")"
        echo -e "Unreachable machines counts: $(grep -c "" "$Var_Unreachable_hosts")"
        grep -i "" "$Var_Unreachable_hosts" > "$Unreachable"
    }

    copy_vfile_to_remote_hosts() {
        ansible all -i "$Var_Reachable_hosts" -m copy -a "src=$Paths dest=\"$VULNERABLE_FILE\""
    }

perform_tar_operations() {
    echo "++++++++++++++++++++++TAR++++++++++++++++++++++++++++++++++++++"
    ansible all -i "$Var_Reachable_hosts" -m shell -a 'for i in $(awk '{print}' "$VULNERABLE_FILE"); do tar -zcf "$i.$(date +"%d-%m-%Y").tar.gz" "$i"; done' &>/dev/null

    echo "++++++++++++++++++++++List TAR.GZ++++++++++++++++++++++++++++++++++++++"
    ansible all -i "$Var_Reachable_hosts" -m shell -a 'for i in $(awk '{print}' "$VULNERABLE_FILE"); do ls -l "$i.$(date +"%d-%m-%Y").tar.gz"; done' >> "$LOG_FILE" &>/dev/null

    echo "++++++++++++++++++++++Remove Jarfiles++++++++++++++++++++++++++++++++++++++"
    ansible all -i "$Var_Reachable_hosts" -m shell -a 'for i in $(awk '{print}' "$VULNERABLE_FILE"); do rm -rf "$i"; done' &>/dev/null

    echo "++++++++++++++++++++++Remove Copied vfile+++++++++++++++++++++++++++"
    ansible all -i "$Var_Reachable_hosts" -m shell -a "rm -rf $VULNERABLE_FILE" &>/dev/null

    echo "++++++++++++++++++++++Generate TAR.csv local+++++++++++++++++++++++++++"
    ansible all -i "$Var_Reachable_hosts" -m shell -a 'for i in $(awk '{print}' "$LOG_FILE"); do echo "$i,$(date +"%d-%m-%Y")"; done' > "$TAR"

    echo "++++++++++++++++++++++DisplayOn screen+++++++++++++++++++++++++++"
 
    awk '{print}' "$TAR"
}

# Call the function
    Apache_Log4j_sort_function
    reachable_unreachable_machines_segregation
    copy_vfile_to_remote_hosts
    perform_tar_operations

    else
   
    echo "Aborted"

fi
