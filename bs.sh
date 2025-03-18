#!/bin/bash

# initial script
printf "       \e[1;4;31;40mWelcome To BashPrO\e[0m\n"
printf "   \e[1;36mYour Personal SyStem Manager\e[0m \n"
echo "**********************************"
read -p "Enter Name:" name
printf "Hello!\e[1;34m$name\e[0m\n"

printf "==============================\n"

LOG_FILE="bashpro.log"

log_message() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "\n[$timestamp] $1" | tee -a "$LOG_FILE"
}

log_message "Script started.\n"

main_menu() {
    while true; do
        echo -e "\e[1;35m===== BashPrO Main Menu =====\e[0m"
        echo "1. User Credential System"
        echo "2. System Information Fetcher"
        echo "3. Network Information Fetcher"
        echo "4. Process Manager"
        echo "5. System Scanner"
        echo "6. Exit"
        read -p "Enter your choice: " choice
        
        log_message "User selected option: $choice"

        case $choice in
            1) 
               log_message "Opening User Credential System"
               user_credential_system ;;  
            2) 
               log_message "Fetching System Information"
               system_information_fetcher ;;  
            3) 
               log_message "Fetching Network Information"
               network_information_fetcher ;;  
            4) 
               log_message "Opening Process Manager"
               process_manager ;;  
            5) 
               log_message "Opening System Scanner"
               system_scan ;;  
            6) 
               log_message "User exited the script."
               echo "Exiting..."
               exit 0
               ;;
            *) 
               log_message "Invalid choice entered: $choice"
               echo "Invalid choice. Try again." ;;
        esac
    done
}




user_credential_system(){

    # adding user credentials
    printf "\n     🔑 \e[1;32mUser Credentials\e[0m\n" 
    echo "Asking permission from user:"
    read -p "Yes Or No:(yes/no)=" answer
    answer=$(echo "$answer" | tr '[:upper:]' '[:lower:]')  # Convert to lowercase
    if [[ "$answer" == "yes" || "$answer" == "s" ]]; then
        echo "Permission Granted"
        echo "Initiating....."
        printf "Done\n\n"

    # user details
        echo "<<<Enter User Details>>>"
        read -p "Enter Full Name:" fullname
        read -p "Enter Age:" age
        read -p "User Status (Working/Student):" status
        
        status=$(echo "$status" | tr '[:upper:]' '[:lower:]')  # Convert to lowercase 
        if [[ $status = "working" ]]; then 
            printf "\e[1mUser is Working\e[0m\n"

            echo "----------------------"
            printf ">>>\e[1;33mUser Details\e[0m<<<\n"
            printf "Full Name:\e[1;31m$fullname\e[0m\n"
            printf "Age:\e[1;31m$age\e[0m\n"
            printf "Status:\e[1;31m$status\e[0m\n"

            echo "----------------------"

            echo "User Details Saved Successfully"
            echo "----------------------"

        elif [[ $status = "student" ]]; then 
            printf "\e[1mUser is Student\e[0m\n"
            
            echo "----------------------"
            printf ">>>\e[1;33mUser Details\e[0m<<<\n"
            printf "Full Name:\e[1;31m$fullname\e[0m\n"
            printf "Age:\e[1;31m$age\e[0m\n"
            printf "Status:\e[1;31m$status\e[0m\n"

            echo "----------------------"

            echo "User Details Saved Successfully"
            echo "----------------------"

        else
            echo "Invalid Status"
        fi

    elif [ $answer = "no" ] || [ $answer = "No" ] || [ $answer = "n" ] || [ $answer = "N" ]; then
        echo "Exiting..."
        echo "Done"
    else
        echo "Invalid Input"
        echo "Exiting..."
        echo "Done" 
    fi
}

    
# system information script
    system_information_fetcher(){
        printf "\nFetching system information.....\n"
        printf "  \e[1;34mSystem Specifications\e[0m\n"
        printf "  \e[1;31mOperating System\e[0m: \e[35m$(uname -o)\e[0m\n"
        printf "  \e[1;31mSystem Architecture\e[0m: \e[35m$(uname -m)\e[0m\n"

# fetch kernel, cpu, memory
        printf "\e[1;33mKernel Info:\e[0m\n"
        printf "    Kernel Name: \e[35m$(uname -s)\e[0m\n"
        printf "    Kernel Version: \e[35m$(uname -v)\e[0m\n"
        printf "    Kernel Release: \e[35m$(uname -r)\e[0m\n"
        printf "\e[1;33mCPU Info:\e[0m\n"
        printf "    CPU Model:\e[35m$(grep -m 1 'model name' /proc/cpuinfo | cut -d ':' -f2)\e[0m\n"
        printf "    CPU Cores: \e[35m$(nproc)\e[0m\n"
        printf "\e[1;33mMemory Info:\e[0m\n"
        printf "    Total RAM:\e[35m$(wmic ComputerSystem get TotalPhysicalMemory | awk 'NR==2 {print $1 / 1024 / 1024 / 1024 " GB"}')\e[0m\n"
        printf "    Available RAM:\e[35m$(wmic OS get FreePhysicalMemory | awk 'NR==2 {print $1 / 1024 / 1024 " GB"}')\e[0m\n"
        printf "    Swap Memory:\e[35m$(wmic OS get TotalVirtualMemorySize | awk 'NR==2 {print $1 / 1024 / 1024 / 1024 " GB"}')\e[0m\n"
    
# fetch motherboard information
        printf "\e[1;33mMotherboard Info:\e[0m\n"
        printf "    Motherboard Manufacturer: \e[35m$(wmic baseboard get Manufacturer | awk 'NR==2')\e[0m\n"
        printf "    Motherboard Model: \e[35m$(wmic baseboard get Product | awk 'NR==2')\e[0m\n"
        printf "    Motherboard Serial Number: \e[35m$(wmic baseboard get SerialNumber | awk 'NR==2')\e[0m\n"

# fetch BIOS information
        printf "\e[1;33mBIOS Info:\e[0m\n"
        printf "    BIOS Vendor: \e[35m$(wmic bios get Manufacturer | awk 'NR==2')\e[0m\n"
        printf "    BIOS Version: \e[35m$(wmic bios get smbiosbiosversion | awk 'NR==2' | tr -d '\r')\e[0m\n"
        printf "    BIOS Release Date: \e[35m$(wmic bios get ReleaseDate | awk 'NR==2 {print substr($1,7,2)"-"substr($1,5,2)"-"substr($1,1,4)}')\e[0m\n"

# fetch disk information
        printf "\e[1;33mDisk Info:\e[0m\n"
        printf "    Disk Model: \e[35m$(wmic diskdrive get Model | awk 'NR==2')\e[0m\n"
        printf "    Disk Serial Number: \e[35m$(wmic diskdrive get SerialNumber | awk 'NR==2')\e[0m\n"
        printf "    Disk Capacity: \e[35m$(wmic diskdrive get Size | awk 'NR==2 {print $1 / 1024 / 1024 / 1024 " GB"}')\e[0m\n"


# Fetch GPU details
    
        printf "\e[1;33mGPU Info:\e[0m\n"
        gpu_model=$(wmic path win32_videocontroller get Caption | awk 'FNR==2')
        gpu_memory=$(wmic path win32_videocontroller get AdapterRAM | awk 'FNR==2 {print ($1 / 1024 / 1024) " MB"}')
        gpu_driver_version=$(wmic path win32_videocontroller get DriverVersion | awk 'FNR==2')
        gpu_status=$(wmic path win32_videocontroller get Status | awk 'FNR==2')
        gpu_resolution=$(wmic path win32_videocontroller get CurrentHorizontalResolution,CurrentVerticalResolution | awk 'FNR==2 {print $1 "x" $2}')
        gpu_refresh_rate=$(wmic path win32_videocontroller get CurrentRefreshRate | awk 'FNR==2 {print $1 " Hz"}')
        gpu_driver_date=$(wmic path win32_videocontroller get DriverDate | awk 'FNR==2 {print substr($1,1,4) "-" substr($1,5,2) "-" substr($1,7,2)}')
        gpu_processor=$(wmic path win32_videocontroller get VideoProcessor | awk 'FNR==2')

# Print GPU information in formatted output
        printf "    GPU Model: \e[35m%s\e[0m\n" "$gpu_model"
        printf "    GPU Video Processor: \e[35m%s\e[0m\n" "$gpu_processor"
        printf "    GPU Memory: \e[35m%s\e[0m\n" "$gpu_memory"
        printf "    GPU Driver Version: \e[35m%s\e[0m\n" "$gpu_driver_version"
        printf "    GPU Status: \e[35m%s\e[0m\n" "$gpu_status"
        printf "    GPU Resolution: \e[35m%s\e[0m\n" "$gpu_resolution"
        printf "    GPU Refresh Rate: \e[35m%s\e[0m\n" "$gpu_refresh_rate"
        printf "    GPU Driver Release Date: \e[35m%s\e[0m\n" "$gpu_driver_date"
    
        printf "System information fetched successfully\n"
      
    }

    


#  network information script
#  network information script
network_information_fetcher(){
    echo -e "\n\e[1;4;35mNetwork Information\e[0m"
    echo -e "\e[1;34mSystem:\e[0m Windows"
    # Fetch Public IP (Masked for Security)
    PUBLIC_IP=$(curl -s ifconfig.me || echo "Unavailable")
    MASKED_PUBLIC_IP="${PUBLIC_IP:0:6}***.***"
    echo -e "\e[1;32mPublic IP:\e[0m ${MASKED_PUBLIC_IP/Unavai***/Unavailable}"
    echo -e "\e[1;32mISP(Internet Service Provider):\e[0m $(curl -s https://ipinfo.io/org | cut -d ' ' -f 2-)"

    # Fetch Private IP
    PRIVATE_IP=$(ipconfig | awk '/IPv4 Address/ {print $NF}' | head -n 1)
    echo -e "\e[1;33mPrivate IP:\e[0m ${PRIVATE_IP:-Not Found}"

    # Active Network Interfaces  
    WIFI_SSID=$(netsh wlan show interfaces | awk -F ': ' '/SSID/ {print $2}' | head -n 1)
    echo -e "\e[1;36mActive Network Interfaces:\e[0m $(netsh interface show interface | grep "Connected" || echo "No active interfaces found.\n")"
    echo -e "\e[1;35mWi-Fi SSID:\e[0m ${WIFI_SSID:-Not Connected}\n"
    

    # Network Speed
    #Install in terminal = [pip install speedtest-cli]
    printf "\e[1;4;35mNOTE:\e[0m \e[1;31mYou must install speedtest-cli to run this command\e[0m\n"
    printf "\e[1mOpen terminal and type\e[0m \e[32mpip install speedtest-cli\e[0m\n"
    printf "\e[1mThen run this script again\e[0m\n\n"
    echo "Do you want to continue? (y/n)"
    read -p "Continue? (y/n): " choice
    if [[ $choice == "y" ]]; then
    printf "\e[1mEnsure that you are connected to the internet...\nFetching network speed...\e[0m\n"
    printf "\e[1mIt may take some time to fetch details..\e[0m\n"
    printf "========================================\n"
    if command -v speedtest-cli &> /dev/null; then
        speedtest-cli --simple | grep -E 'Ping|Download|Upload'
    else
        python3 -c "
import speedtest
st = speedtest.Speedtest()
st.get_best_server()
print(f'Ping: {st.results.ping} ms\nDownload: {st.download() / 1_000_000:.2f} Mbps\nUpload: {st.upload() / 1_000_000:.2f} Mbps')" || echo "Python speedtest failed!"
    fi
else
    echo "Exiting..."
    exit 1
fi
}   




#!/bin/bash

    process_manager(){
        echo -e "\n\e[1;36m       USER PROCESS REPORT            "
        echo -e "\e[1;36m=================================\e[0m"

    # Check Running Processes
        echo -e "\e[33mScanning running processes...\e[0m"
        if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
            total_processes=$(tasklist | wc -l)
        else
            total_processes=$(ps aux | wc -l)
        fi
        echo -e "\e[32m✔ Total running processes: $((total_processes - 3))\e[0m"

    # Memory Usage
        echo -e "\e[33mChecking memory usage...\e[0m\n"
        total_ram=$(wmic ComputerSystem get TotalPhysicalMemory | awk 'NR==2 && $1 ~ /^[0-9]+$/ {print $1 / 1024 / 1024 / 1024}')
        available_ram=$(wmic OS get FreePhysicalMemory | awk 'NR==2 && $1 ~ /^[0-9]+$/ {print $1 / 1024 / 1024}')


        if [[ -n "$total_ram" && -n "$available_ram" ]]; then
            used_ram=$(awk "BEGIN {print $total_ram - $available_ram}")
        else
            used_ram="N/A"
        fi

    
        printf "Total RAM: \e[35m%.2f GB\e[0m\n" "$total_ram"
        printf "Available RAM: \e[35m%.2f GB\e[0m\n" "$available_ram"
        printf "Used RAM: \e[35m%s GB\e[0m\n" "$used_ram"

        if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        total_mem=$(wmic OS get FreePhysicalMemory | awk 'NR==2 {printf "%.2f GB\n", $1/1024/1024}')
        else
            total_mem=$(ps aux --sort=-%mem | awk '{sum+=$6} END {printf "%.2f GB\n", sum/1024/1024}')
        fi

        echo -e "\e[34mℹ Total memory used by processes: $total_mem\e[0m"


    # Cache & Temporary Files
        echo -e "\e[33mScanning for temporary/cache files...\e[0m"

    # Set cache directories based on OS
        if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
            cache_dirs=("C:/Users/$USERNAME/AppData/Local/Temp" "C:/Windows/Temp")
        else
            cache_dirs=("/var/tmp" "/tmp" "$HOME/.cache" "$HOME/.mozilla/firefox" "$HOME/.config/google-chrome")
        fi

        total_cache_files=0
        total_deleted=0

        for dir in "${cache_dirs[@]}"; do
            if [ -d "$dir" ]; then
                count=$(find "$dir" -type f 2>/dev/null | wc -l)
                total_cache_files=$((total_cache_files + count))

            # Delete only files older than 7 days
                deleted=$(find "$dir" -type f -mtime +7 -delete -print 2>/dev/null | wc -l)
                total_deleted=$((total_deleted + deleted))
            fi
        done

        if [ "$total_cache_files" -gt 0 ]; then
            echo -e "\e[31m⚠ Found $total_cache_files temporary/cache files.\e[0m\n"
        else
            echo -e "\e[32m✔ No temporary/cache files found.\e[0m\n"
        fi

        if [ "$total_deleted" -gt 0 ]; then
            echo -e "\e[31m⚠ Deleted $total_deleted cache files.\e[0m"
            echo -e "\e[33mPartial Cleanup Completed.\e[0m"
            echo -e "Removed $total_deleted files, but some remain."
            echo -e "Files older than 7 days were deleted.\n"
            echo -e "\e[33m⚠ Some files may still be in use or require manual deletion.\e[0m\n"
            echo -e "Try running the script as an administrator for complete cleanup."
        else
            echo -e "\e[33m⚠ Some files were not deleted. Possible reasons:\e[0m"
            echo -e "   🔹 Some files are locked by active programs."
            echo -e "   🔹 No files met the deletion criteria (older than 7 days)."
            echo -e "   🔹 Admin privileges required for complete cleanup."
            echo -e "\e[32m✔ No cleanup needed.\e[0m"
            echo -e "\e[32m✔ System is clean!\e[0m\n"
        fi



        echo -e "\e[1;36m        CPU & DISK USAGE REPORT    \e[0m" 
        echo -e "\e[1;36m=======================================\e[0m"

    # CPU Usage
        echo -e "\e[33mChecking CPU usage...\e[0m"
        if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
            cpu_usage=$(wmic cpu get LoadPercentage | awk 'NR==2 {print $1}')
            total_processes=$(tasklist | wc -l)  # Count total processes correctly
        else
            cpu_usage=$(ps -eo %cpu --no-headers | awk '{sum+=$1} END {print sum}')
            total_processes=$(ps -e --no-headers | wc -l)
        fi

        echo -e "Current CPU usage: \e[35m$cpu_usage%\e[0m"
        echo -e "Total running processes: \e[35m$((total_processes - 3))\e[0m" 

    # CPU Alert (Fixed for Git Bash)
        cpu_limit=80
        cpu_int=${cpu_usage%.*}  # Remove decimal part for comparison
        if [ "$cpu_int" -gt "$cpu_limit" ]; then
            echo -e "\e[1;31m🚨 WARNING: High CPU Usage! ($cpu_usage%)\e[0m"
        fi


    # Disk Usage
        echo -e "\e[33m\nChecking disk usage...\e[0m"
        printf "Total Disk Capacity: \e[35m$(wmic logicaldisk get Size | awk 'NR==2 {print $1 / 1024 / 1024 / 1024 " GB"}')\e[0m\n"
        printf "Used Disk Space: \e[35m$(wmic logicaldisk get FreeSpace, Size | awk 'NR>1 && $1!="" {total+=$2; free+=$1} END {print (total-free)/1024/1024/1024 " GB"}')\e[0m\n"
        printf "Available Disk Space:\e[35m$(wmic logicaldisk get freespace | awk 'NR==2 {print $1 / 1024 / 1024 / 1024 " GB"}')\e[0m\n"

    # Disk Space Alert (Fixed for Git Bash)
    # Ensure available_disk is not empty before comparison
        if [[ -n "$available_disk" && "$available_disk" =~ ^[0-9]+$ && "$available_disk" -lt "$disk_limit" ]]; then
            echo -e "\e[1;31m🚨 CRITICAL: Low Disk Space! ($available_disk GB left)\e[0m"
        fi


        echo -e "\e[1;36========================================\e[0m"
        echo -e "\e[1;36m           SYSTEM CLEANUP        \e[0m"
        echo -e "\e[1;36m=======================================\e[0m"

    # Define paths
        TEMP_DIR="/c/Users/$USERNAME/AppData/Local/Temp"
        RECYCLE_BIN="C:\$Recycle.Bin"
        WINDOWS_TEMP="/c/Windows/Temp"
        PREFETCH="C:\Windows\Prefetch"

        echo -e "\e[1;33mCleaning temporary files...\e[0m"
        rm -rf "$TEMP_DIR"/* 2>/dev/null

        echo -e "\e[1;33mCleaning Recycle Bin...\e[0m"
        powershell.exe -Command 'Clear-RecycleBin -Confirm:$false' 2>/dev/null

        echo -e "\e[1;33mCleaning System cache...\e[0m"
        rm -rf "$WINDOWS_TEMP"/* 2>/dev/null
        powershell.exe -Command "Remove-Item -Path '$PREFETCH\*' -Force" 2>/dev/null

        echo -e "\e[1;32m✔ System cleanup completed successfully!\e[0m"
     
    }
    
    

    system_scan() {
        date
        # Start System Scan
        echo -e "\n\e[1;34mStarting System Scan...\e[0m"
        # total time last booted
        echo -e "System Uptime: \e[32m$(cat /proc/uptime | awk '{print int($1/3600) " hours, " int(($1%3600)/60) " minutes"}')\e[0m"
        # exact date & time last booted
        echo -e "System Boot Time: \e[32m$(net stats workstation | awk '/since/ {print $3, $4, $5}')\e[0m"
        # Battery Status
        printf "Current Battery Status: %s%% \e[35m$(wmic path Win32_Battery get EstimatedChargeRemaining | awk 'NR==2')\e[0m\n"    
        echo "--------------------------------------------------------"
        echo "System Security and Performance Scan"
        echo "Estimated scan time: ~5-10 minutes (varies based on system size)."
        echo "Please do not interrupt the process."
        echo -e "--------------------------------------------------------\n"

        # Run Windows Defender Quick Scan
        echo -e "\e[33mRunning Windows Defender Quick Scan...\e[0m"
        powershell.exe -Command "Start-MpScan -ScanType QuickScan" > /dev/null 2>&1
        echo -e "\e[32mQuick Scan completed. Proceeding with analysis...\e[0m"

        # Define directories to scan
        dirs=("C:/Users/$USERNAME/Downloads" "C:/Users/$USERNAME/Desktop" "C:/Windows/System32" "C:/ProgramData")

        # Initialize counters
        hidden_count=0
        large_count=0
        suspicious_count=0
        suspicious_files_deleted=0
        suspicious_ports=0
        outdated_apps=0
        terminated_processes=0
        low_risk=0
        high_risk=0

        # Define suspicious file extensions
        suspicious_ext=("exe" "dll" "bat" "vbs" "js" "scr" "cmd" "pif")

        # Scan for hidden and large files
        echo -e "\e[36mScanning for hidden and large files...\e[0m"
        for dir in "${dirs[@]}"; do
            hidden_count=$((hidden_count + $(find "$dir" -type f -name ".*" 2>/dev/null | wc -l)))
            large_count=$((large_count + $(find "$dir" -type f -size +50M 2>/dev/null | wc -l)))
        done
        echo -e "\e[32mFile scan completed.\e[0m"

        # Scan for suspicious files and delete them
        echo -e "\e[36mScanning for suspicious files...\e[0m"
        for ext in "${suspicious_ext[@]}"; do
            files=$(find "C:/Users/$USERNAME" -type f -iname "*.$ext" 2>/dev/null)
            count=$(echo "$files" | wc -l)
            suspicious_count=$((suspicious_count + count))
            if [[ $count -gt 0 ]]; then
                echo "$files" | xargs rm -f 2>/dev/null
                suspicious_files_deleted=$((suspicious_files_deleted + count))
            fi
        done
        echo -e "\e[32mSuspicious file scan completed.\e[0m"

        # Check for outdated applications
        echo -e "\e[36mChecking for outdated applications...\e[0m"
        outdated_apps=$(powershell.exe -Command "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion | Out-String" | grep -E "Adobe|Java|Flash|Reader" | wc -l)
        echo -e "\e[32mApplication check completed.\e[0m"

        # Scan for suspicious open ports
        echo -e "\e[36mScanning for suspicious ports...\e[0m"
        suspicious_ports=$(netstat -ano | findstr -r " :135 |:445 |:4444 |:8080 |:12345 |:31337" | wc -l)
        echo -e "\e[32mPort scan completed.\e[0m"

        # Check for suspicious processes and terminate them
        echo -e "\e[36mScanning for suspicious processes...\e[0m"
        while IFS= read -r process; do
            if echo "$process" | grep -E -i "malware|trojan|spyware|ransomware" > /dev/null; then
                pid=$(echo "$process" | awk '{print $2}')
                taskkill.exe /PID "$pid" /F > /dev/null 2>&1
                terminated_processes=$((terminated_processes + 1))
            fi
            
            # Categorize risk level
            if [[ $suspicious_count -le 50 ]]; then
                low_risk=1
            else
                high_risk=1
            fi

        done < <(wmic process get Name,ProcessId | tail -n +2)
        echo -e "\e[32mProcess scan completed.\e[0m"

        # Display scan summary
        echo -e "\n\e[34mScan Summary:\e[0m"
        echo -e "Hidden Files: $hidden_count | Large Files: $large_count"
        echo -e "Suspicious Files: $suspicious_count | Suspicious Files Deleted: $suspicious_files_deleted"
        echo -e "Terminated Processes: $terminated_processes"
        echo -e "Outdated Apps: $outdated_apps | Suspicious Ports: $suspicious_ports"

        # Display Risk Level Alert
        if [[ $high_risk -gt 0 ]]; then
            echo -e "\e[31m\nSystem scan complete. High risk detected! Immediate action recommended.\e[0m"
        elif [[ $low_risk -gt 0 ]]; then
            echo -e "\e[33m\nSystem scan complete. Low risk detected. Monitor the system.\e[0m"
        fi

        # Save scan results to a log file
        log_file="C:/Users/$USERNAME/Desktop/system_scan_report.txt"
        {
            echo "==== System Scan Report ===="
            echo "Date: $(date)"
            echo "Hidden Files: $hidden_count"
            echo "Large Files: $large_count"
            echo "Suspicious Files: $suspicious_count"
            echo "Suspicious Files Deleted: $suspicious_files_deleted"
            echo "Suspicious Ports: $suspicious_ports"
            echo "Outdated Applications: $outdated_apps"
            echo "Terminated Processes: $terminated_processes"
            echo "Risk Level: $( [[ $high_risk -gt 0 ]] && echo "High Risk" || echo "Low Risk" )"
            echo "==============================="
        } > "$log_file"

        echo -e "\e[1;32mLog file saved at: $log_file\e[0m"
     
    }
      
    main_menu