#!/bin/bash

clear
tput setaf 10
echo "---------------------"
echo "  _   _   _   _   _ "
echo " / \ / \ / \ / \ / \ "
echo "( N | g | i | n | x )"
echo " \_/ \_/ \_/ \_/ \_/ "
echo "Fast Intuitive Secure"
echo "---------------------"
echo ""
echo "Management tool for servers with Nginx"
echo ""

PS3="Select an option: " 

select opt in Start Stop Restart Status Reload Test-config Version Info Exit; 

do 
        case $opt in    
                Start)   
                        sudo /etc/init.d/nginx start
                        ;; 
                Stop)  
                        sudo /etc/init.d/nginx stop
                        ;; 
                Restart)
                        sudo /etc/init.d/nginx restart
                        ;; 
                Status)
                        sudo /etc/init.d/nginx status
                        ;;
                Reload)
                        sudo /etc/init.d/nginx reload
                        ;; 
                Test-config)
                        sudo nginx -t
                        ;; 
                Version)
                        sudo nginx -V
                        ;; 
                Info)
                        echo "[#]Here you will find what each option is for"
                        echo "1: Start the Nginx web server."
                        echo "2: Stopping the Nginx web server will cause the web not to be found."
                        echo "3: Restart the Nginx web server, in case of errors it is the first command to go to."
                        echo "4: Indicates the status of the Nginx web server, is ti used to see if it is active or if the configuration has errors."
                        echo "5: It loads the new configuration, starts new worker processes with the new configuration, and stops old worker processes. Basically, delete everything and reinstall."
                        echo "6: This command is used to check the Nginx configuration for system or syntax errors."
                        echo "7: This command is used to view the current version of Nginx along with configuration options."
                        echo "8: This command is the one you are seeing now, it is used to describe the other commands and train the staff/user on how to use this tool."
                        echo "9: With this command you exit the tool."
                        echo "[#]It can still be complicated to manage an Nginx server by command if you have never been in front of a Bash, that is why a teenager who does not know anything about English has created this script, to help you with this swampy terrain that we call computing."
                        echo "[#]Good luck! :)"
                        ;;
                Exit)  
                        break 
                        ;; 
                *) 
                        echo "$REPLY That option does not exist, put a number." 
                        ;; 
        esac 
done
