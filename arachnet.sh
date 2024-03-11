#!/bin/bash

red='\033[0;31m'
purple='\033[0;35m'
nc='\033[0m'

banner() {
    echo -e "${red}---------------------------------------${nc}"
    echo -e "${red}             $1${nc}"
    echo -e "${red}---------------------------------------${nc}"
}

enumerate() {
    clear
    banner "Enumeration"
    mkdir -p dump
    python3 DnsDumpster/main.py -u $domain > dump/output_$domain.txt 
    printf "Enumerated output after running dnsdumpster\n"
    python3 seg.py $domain
    clear
    echo -e "${purple}Enumerated output${nc}"
    ls
    pwd
    echo -e "${red}1. Exit${nc}"
    echo -e "${red}2. Go back${nc}"
    read option
    case "$option" in
        "2")
             menu
             ;;
        *)
             ;;
    esac

}



vuln_scan() {
    clear
    banner "Vulnerability Scan "
    echo -e "${purple}Choose an option:${nc}"
    echo -e "${red}1. Domain${nc}"
    echo -e "${red}2. Text File${nc}"
    echo -e "${red}b. Back${nc}"
    read option

    case "$option" in
        1)
            nuclei -u $domain
            ;;
        2)
            echo -e "${purple}Choose an option:${nc}"
            echo -e "${red}1. Domain${nc}"
            echo -e "${red}2. IP${nc}"
            read option

            case "$option" in
                1)
                    while IFS= read -r subdomain
                    do
                        nuclei -l $subdomain >> enum/subdomain.txt
                    done < dump/subdomains.txt
                    ;;
                2)
                    while IFS= read -r ip
                    do
                        nmap $ip >> enum/ip.txt
                    done < ip.txt
                    ;;
                *)
                    echo -e "${red}Invalid option, please try again${nc}"
                    ;;
            esac
            ;;
        "b")
            menu
            ;;
        *)
            echo -e "${red}Invalid option, please try again${nc}"
            vuln_scan
            ;;
    esac
}


test_sqli() {
    clear
    banner "SQL Injection Test"
    echo -e "${purple}Choose an option:${nc}"
    echo -e "${red}1. New Subdomain${nc}"
    echo -e "${red}2. New Domain${nc}"
    echo -e "${red}3. Original Domain${nc}"
    echo -e "${red}4. Select Domain${nc}"
    echo -e "${red}b. Back${nc}"
    read option

    case "$option" in
        1)
            echo -e "${purple}Enter the filename that contains subdomains:${nc}"
            read filename
            python3 sqlmap/sqlmap.py -f $filename -o output.txt
            ;;
        2)
            echo -e "${purple}Enter the URL to scan:${nc}"
            read url
            python3 sqlmap/sqlmap.py -u $url -o output.txt
            ;;
        3)
            python3 sqlmap/sqlmap.py -f original_domain.txt -o output.txt
            ;;
        4)
            echo -e "${purple}Select a domain:${nc}"
            select domain in $(cat dump/subdomains.txt); do
                python3 sqlmap/sqlmap.py -f $domain -o output.txt
                break
            done
            ;;
        "b")
            menu
            ;;
        *)
            echo -e "${red}Invalid option, please try again${nc}"
            test_sqli
            ;;
    esac
}


test_xss() {
    clear
    banner "Cross-Site Scripting Test"
    echo -e "${purple}Choose an option:${nc}"
    echo -e "${red}1. New Subdomain${nc}"
    echo -e "${red}2. New Domain${nc}"
    echo -e "${red}3. Original Domain${nc}"
    echo -e "${red}4. Select Domain${nc}"
    echo -e "${red}b. Back${nc}"
    read option

    case "$option" in
        1)
            echo -e "${purple}Enter the filename that contains subdomains:${nc}"
            read filename
            python3 xss/main.py -f $filename -o output.txt
            ;;
        2)
            echo -e "${purple}Enter the URL to scan:${nc}"
            read url
            python3 xss/main.py -u $url -o output.txt
            ;;
        3)
            python3 xss/main.py -f original_domain.txt -o output.txt
            ;;
        4)
            echo -e "${purple}Select a domain:${nc}"
            select domain in $(cat dump/subdomains.txt); do
                python3 xss/main.py -f $domain -o output.txt
                break
            done
            ;;
        "b")
            menu
            ;;
        *)
            echo -e "${red}Invalid option, please try again${nc}"
            test_xss
            ;;
    esac
}

test_idor() {
    clear
    banner "IDOR Test"
    echo -e "${purple}Choose an option:${nc}"
    echo -e "${red}1. New Subdomain${nc}"
    echo -e "${red}2. New Domain${nc}"
    echo -e "${red}3. Original Domain${nc}"
    echo -e "${red}4. Select Domain${nc}"
    echo -e "${red}b. Back${nc}"
    read option

    case "$option" in
        1)
            echo -e "${purple}Enter the filename that contains subdomains:${nc}"
            read filename
            python3 idor/iodor.py -f $filename -o output.txt
            ;;
        2)
            echo -e "${purple}Enter the URL to scan:${nc}"
            read url
            python3 idor/iodor.py -u $url -o output.txt
            ;;
        3)
            python3 idor/iodor.py -f original_domain.txt -o output.txt
            ;;
        4)
            echo -e "${purple}Select a domain:${nc}"
            select domain in $(cat dump/subdomains.txt); do
                python3 idor/iodor.py -f $domain -o output.txt
                break
            done
            ;;
        "b")
            menu
            ;;
        *)
            echo -e "${red}Invalid option, please try again${nc}"
            test_idor
            ;;
    esac
}

scope() {
    clear
    banner "Scope Options"
    files=(enum/*.txt)
    echo -e "${purple}Select a file to edit:${nc}"
    echo -e "${purple}or${nc}"
    echo -e "${purple}1 for menu${nc}"
    echo -e "${purple}2 for back${nc}"
    select fname in "${files[@]}" ; do
        case $fname in
            "")
                echo -e "${red}Invalid option, try again.${nc}"
                scope
                ;;
            "1")
                echo -e "${purple}Going back to menu...${nc}"
                menu
                return
                ;;
            "2")
                echo -e "${purple}Going back...${nc}"
                scope
                return
                ;;
            *)
                echo -e "${purple}You selected ${fname}${nc}"
                echo -e "${purple}Contents of the file:${nc}"
                cat "$fname"
                echo -e "${purple}Do you want to add or remove an item?${nc}"
                echo "1) Add"
                echo "2) Remove"
                read -p "Enter your choice (1 or 2): " choice
                case $choice in
                    1)
                        read -p "Enter the item to add: " item
                        echo "$item" >> "$fname"
                        echo -e "${purple}Item added.${nc}"
                        ;;
                    2)
                        read -p "Enter the item to remove: " item
                        sed -i "/$item/d" "$fname"
                        echo -e "${purple}Item removed.${nc}"
                        ;;
                    *)
                        echo -e "${red}Invalid option, try again.${nc}"
                        ;;
                esac
                break
                ;;
        esac
    done
}

menu() {
    clear
    echo "${red}    _                      _                 _   ${nc}"
    echo "${red}   / \    _ __  __ _   ___| |__  _ __   ___ | |_ ${nc}"
    echo "${red}  / _ \  | '__/ _\` | / __| '_ \| '_ \ / _ \  __|${nc}"
    echo "${red} / ___ \ | |  | (_| |  (__| | | | | | |  __/  |_ ${nc}"
    echo "${red}/_/   \_ \_|   \__,_| \___|_| |_|_| |_|\___| \__|${nc}"
    echo "${red}   ${nc}"
    echo "${red}   ${nc}"
    read -p "Enter the domain: " domain
    echo "${red}   ${nc}"
    echo "${red}   ${nc}"

        echo "${purple}1. Enumerate${nc}"
        echo "${purple}2. Vuln Scan${nc}"
        echo "${purple}3. Test for Sqli${nc}"
        echo "${purple}4. Test for Xss${nc}"
        echo "${purple}5. Test for IDOR${nc}"
        echo "${purple}6. Scope options ${nc}"
        echo "${purple}7. Exit${nc}"
        echo "${red}   ${nc}"
        echo  "Please enter an option: "
        read option
        case $option in
            1) enumerate ;;
            2) vuln_scan ;;
            3) test_sqli ;;
            4) test_xss ;;
            5) test_idor ;;
            6) scope ;;
            7) echo "Exiting..."
               exit 0
               ;;
            *) echo "Invalid option, please try again"
               menu
               ;;
        esac

}

main() {
    menu
}

main
