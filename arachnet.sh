#!/bin/bash

red='\033[0;31m'
purple='\033[0;35m'
nc='\033[0m' # No Color

enumerate() {
    clear
    echo "Enumerate selected"
    mkdir -p dump
    python3 DnsDumpster/main.py -u $domain > dump/output_$domain.txt 
    printf "Enumerated output after running dnsdumpster\n"
    python3 seg.py $domain
    clear
    echo "Enumerated output"
    ls
    pwd
}

vuln_scan() {
    echo "Choose an option: [d/txt]"
    read option

    if [ "$option" = "d" ]; then
        nuclei -u $domain # ask for url 
    elif [ "$option" = "txt" ]; then
        echo "Choose an option: [domain/ip]"
        read option

        if [ "$option" = "domain" ]; then
            while IFS= read -r subdomain
            do
                nuclei -l $subdomain >> vuln/all/subdomain.txt
            done < dump/subdomains.txt
        elif [ "$option" = "ip" ]; then
            while IFS= read -r ip
            do
                nmap $ip >> vuln/all/ip.txt
            done < ip.txt
        fi
    fi
}

test_sqli() {
    echo "Test for Sqli selected"
}

test_xss() {
    echo "Test for Xss selected"
    echo -e "\033[0;35mChoose an option: [new sub /new dom/og dom/select dom]\033[0m"
    read option

    if [ "$option" = "new sub" ]; then
        echo -e "\033[0;35mEnter the filename that contains subdomains:\033[0m"
        read filename
        python3 xss/main.py -f $filename -o output.txt
    elif [ "$option" = "new dom" ]; then
        echo -e "\033[0;35mEnter the URL to scan:\033[0m"
        read url
        python3 xss/main.py -u $url -o output.txt
    elif [ "$option" = "og dom" ]; then
        python3 xss/main.py -f original_domain.txt -o output.txt
    elif [ "$option" = "select dom" ]; then
        echo -e "\033[0;35mSelect a domain:\033[0m"
        select domain in $(cat dump/subdomains.txt); do
            python3 xss/main.py -f $domain -o output.txt
            break
        done
    fi
}

test_idor() {
    echo "Test for IDOR selected"
}
menu() {
    clear
    echo "${red}    _                      _                 _   ${nc}"
    echo "${red}   / \    _ __  __ _   ___| |__  _ __   ___ | |_ ${nc}"
    echo "${red}  / _ \  | '__/ _\` | / __| '_ \| '_ \ / _ \  __|${nc}"
    echo "${red} / ___ \ | |  | (_| |  (__| | | | | | |  __/  |_ ${nc}"
    echo "${red}/_/   \_ \_|   \__,_| \___|_| |_|_| |_|\___| \__|${nc}"
    read -p "Enter the domain: " domain


        echo "${purple}1. Enumerate${nc}"
        echo "${purple}2. Vuln Scan${nc}"
        echo "${purple}3. Test for Sqli${nc}"
        echo "${purple}4. Test for Xss${nc}"
        echo "${purple}5. Test for IDOR${nc}"
        echo "${purple}6. Exit${nc}"
        echo  "Please enter an option: "
        read option
        case $option in
            1) enumerate ;;
            2) vuln_scan ;;
            3) test_sqli ;;
            4) test_xss ;;
            5) test_idor ;;
            6) echo "Exiting..."
               exit 0
               ;;
            *) echo "Invalid option, please try again"
               ;;
        esac

}

main() {
    menu
}

main