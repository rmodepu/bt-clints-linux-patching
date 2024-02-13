#!/bin/bash

################################################################################
# Description: This script extracts necessary information from the input CSV  #
#              file and formats.                       #
# Input:       OpenSSL-Java.csv (input CSV file)                            #        #
################################################################################

DOWNLOAD_FOLDER="/mnt/c/Users/rmodepu/Downloads"

echo "Get the latest file in the download folder:"
find "$DOWNLOAD_FOLDER" -type f -newermt $(date +%Y-%m-%d) ! -newermt $(date -d "+1 day" +%Y-%m-%d) | grep -v "vulns.csv"

read -p "Enter the latest file (including any spaces or special characters): " file

file_path="$DOWNLOAD_FOLDER/$file"

# Remove single quotes from file_path
file_path="${file_path//\'/}"

if [ -f "$file_path" ]; then
    echo "List/Count the file content:" $(awk '{ print }' "$file_path" | wc -l)
else
    echo "File not found: $file_path"
fi

echo "================================================"

# Declare the Variables
INPUT_FILE="$file_path"
Inventory="/home/rmodepu/Ansible/inventory_openssl"
paths="/home/rmodepu/openssl.vfile"
Total_Machines=$(grep -i "" "$INPUT_FILE" | egrep "wsl|ltl" | awk -F"," '{ print $3 }' | awk '!visited[$0]++' | wc -l)
List_of_paths="$(grep -i "" /home/rmodepu/openssl.vfile)"

extract_information() {
    PluginOutput="<plugin_output>"

    # Check if PluginOutput matches the specified format
    if [[ "$PluginOutput" == *"<plugin_output>"* ]]; then

        # Extract paths from vulns.csv
        local machines_names=$(grep -i "" "$INPUT_FILE" | egrep "wsl|ltl" | awk -F"," '{ print $3 }' | awk '!visited[$0]++' > "$Inventory")
        local installed_path=$(grep -i "" "$INPUT_FILE" | grep -i "Path" | awk -F":" '{ print $2 }' | sed 's/^ //g' | sed -n 's/\(.*\)\\\\\\.*/\1/p' | awk '!visited[$0]++' | egrep -wv "Tanium|NX|TaniumClient" > "$paths")
        local installed_pathcount=$(grep -i "" "$INPUT_FILE" | grep -i "Path" | awk -F":" '{ print $2 }' | sed 's/^ //g' | sed -n 's/\(.*\)\\\\\\.*/\1/p' | awk '!visited[$0]++' | egrep -wv "Tanium|NX|TaniumClient" | wc -l)

        echo -e "Check the Paths : \n$List_of_paths"
        echo -e "Total PathCount: $installed_pathcount"
        echo -e "Total Machines: $Total_Machines"
    else
        # Extract paths from vulns.csv
        # You need to fill in what you want to do if the PluginOutput doesn't match
        # For now, let's just print a message
        echo "PluginOutput does not match specified format"
    fi
}

# Main function
main() {
    extract_information
}

# Run the main function
main

# Run the main function
read -rp "Remediation OpenSSL ..y/n:" Action

if [ "$Action" == "y" ]; then
    OpenSSL_function() {
        Var_Total_Hosts="/home/rmodepu/OpenSSL/inventory_OpenSSL1"
        Var_Reachable_hosts="/home/rmodepu/OpenSSL/inventory_online"
        Var_Unreachable_hosts="/home/rmodepu/OpenSSL/inventory_offline"
        Save_Archived_file="/mnt/c/Users/rmodepu/Desktop/CSVfile/OpenSSL"
    }

    reachable_unreachable_machines_segregation() {
        echo "+++++++++++++++++++++++++++++++++++++++++++"
        echo -e "\e[0;31m *****Remediation initialized*****\e[0m"
        read -rp "Enter y/n to Sort Reachable/Unreachable Hosts: " Action
        echo

        if [ "${Action}" == "y" ]; then
            echo -e "\e[0;31m***Please Wait for a couple of minutes to sort***.........\e[0m"
            #ansible all -i "$Inventory" -a "id" -o
            ansible all -i "$Inventory" -a "id" -o > "$Var_Total_Hosts"
            grep -i "" "$Var_Total_Hosts" | grep -i CHANGED | awk -F "|" '{ print $1 }' | egrep -wv "ECDSA|WARNING|host" > "$Var_Reachable_hosts"
            grep -i "" "$Var_Total_Hosts" | grep -i UNREACHABLE | awk -F "|" '{ print $1 }' > "$Var_Unreachable_hosts"
        fi

        echo -e "Reachable Machines counts: $(grep -c "" "$Var_Reachable_hosts")"
        echo -e "Unreachable machines counts: $(grep -c "" "$Var_Unreachable_hosts")"
        grep -i "" "$Var_Unreachable_hosts" > "$Save_Archived_file/unreachable-$(date +"%d.%m.%Y").csv"
    }

    copy_vfile_to_remote_hosts() {
        ansible all -i "$Var_Reachable_hosts" -m copy -a "src=$paths dest=/var/tmp/vfile1"
    }

    perform_tar_operations() {
        # Save the output of Tar,gz
        save_output=$(grep -i "" "$Save_Archived_file/OpenSSL_$(date +"%d-%m-%Y").TAR.csv")

        echo "++++++++++++++++++++++TAR++++++++++++++++++++++++++++++++++++++"
        ansible all -i "$Var_Reachable_hosts" -m shell -a 'for i in $(cat /var/tmp/vfile1); do tar -zcf "$i.$(date +"%d-%m-%Y").tar.gz" "$i"; done' &>/dev/null
        echo "++++++++++++++++++++++List TAR.GZ++++++++++++++++++++++++++++++++++++++"
        ansible all -i "$Var_Reachable_hosts" -m shell -a 'for i in $(cat /var/tmp/vfile1); do ls -l "$i.$(date +"%d-%m-%Y").tar.gz"; done >>/var/tmp/OpenSSL1' &>/dev/null
        echo "++++++++++++++++++++++Remove VulnerableFile++++++++++++++++++++++++++++++++++++++"
        ansible all -i "$Var_Reachable_hosts" -m shell -a 'for i in $(cat /var/tmp/vfile1); do rm -rf "$i"; done'
        echo "++++++++++++++++++++++Remove /var/tmp/vfile1+++++++++++++++++++++++++++"
        ansible all -i "$Var_Reachable_hosts" -m shell -a "rm -rf /var/tmp/vfile1"
        echo "++++++++++++++++++++++TAR.csv+++++++++++++++++++++++++++"
        ansible all -i "$Var_Reachable_hosts" -m shell -a 'grep -i "`date +'%d-%m-%Y'`.tar.gz" /var/tmp/OpenSSL1 | awk -F" " "{ print \$1,\$9 }"' > "$Save_Archived_file/OpenSSL_$(date +"%d-%m-%Y").TAR.csv"
        echo "++++++++++++++++++++++Display On Screen+++++++++++++++++++++++++++"
        # Display the Hostname and Files which are Tar. 
        echo "$save_output"
    }

    # Call the functions
    main
    OpenSSL_function
    reachable_unreachable_machines_segregation
    copy_vfile_to_remote_hosts
    perform_tar_operations
else
    echo "Aborted"
fi
