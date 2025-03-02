#!/bin/bash
echo "let's get started"
read -p "enter name:" name
echo "Hello! $name"

echo "Enter Some Credentials"
read -p "Yes Or No:(yes/no)=" answer
if [ $answer = "yes" ]; then
    echo "Initiating..."
    echo "Done"
    read -p "Enter Full Name:" fullname
    read -p "Enter Age:" age
    read -p "User Status (Working/Student):" status

    if [ $status = "working" ]; then
        echo "User is Working"
    elif [ $status = "student" ]; then
        echo "User is Student"
    else
        echo "Invalid Status"
    fi

    echo "User Details:"
    echo "Full Name: $fullname"
    echo "Age: $age"
    echo "Status: $status"


elif [ $answer = "no" ]; then
    echo "Exiting..."
    echo "Done"
else
    echo "Invalid Input"
    echo "Exiting..."
    echo "Done" 
fi