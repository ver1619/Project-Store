#!/bin/bash

# initial script
printf "     \e[1;4;31;40mWelcome To BashPrO\e[0m\n"
printf "🏛️  \e[1;36mA Windows System Library\e[0m📚\n"
echo "******************************"
read -p "Enter Name:" name
printf "Hello!\e[1;34m$name\e[0m\n"

printf "==============================\n"

# adding user credentials
printf "   \e[1;32mUser Credentials Manager\e[0m\n\n" 
echo "Asking permission from user:"
read -p "Yes Or No:(yes/no)=" answer
if [ $answer = "yes" ] || [ $answer = "Yes" ] || [ $answer = "s" ] || [ $answer = "S" ]; then
    echo "Initiating....."
    printf "Done\n\n"

    read -p "Enter Full Name:" fullname
    read -p "Enter Age:" age
    read -p "User Status (Working/Student):" status

    if [ $status = "working" ] || [ $status = "Working" ]; then
        printf "\e[1mUser is Working\e[0m\n"
    elif [ $status = "student" ] || [ $status = "Student" ]; then
        printf "\e[1mUser is Student\e[0m\n"
         
    echo "---------------------"
     
    printf ">>>\e[1;33mUser Details\e[0m<<<\n"
    printf "Full Name:\e[1;31m$fullname\e[0m\n"
    printf "Age:\e[1;31m$age\e[0m\n"
    printf "Status:\e[1;31m$status\e[0m\n"

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

# end of script 