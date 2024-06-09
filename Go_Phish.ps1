########################################################################################################################################################
## Created by: MrMarl3y
## Date created - 06/09/2024
## Revision number 1.0
#######################################################################################################################################################
##
## This tool is designed for system admins to remove phishing emails as well as perform phishing attacks on their end users.
## 
#######################################################################################################################################################

## Set execution policy

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

## Install required modules and import them if needed

$AlreadyImportedModules = Get-Module
$ModulesToCheck = @(“ExchangeOnlineManagement”)

ForEach($i in $ModulesToCheck)
    {
        If($AlreadyImportedModules.Name -notcontains $i)
            {
                Import-Module $i
            }
    }

## Connect to Exchange online and to Security & Compliance Center. This will require the user to input thier admin credentials.

Connect-ExchangeOnline

Connect-IPPSSession


## Begin program

While ($True) 
{
    ## This function will search for the emails in question and prompt user to approve removal and blocking of sender
    Function Get-Phish 
    {
        ## Define Variables needed for search

        $Name = Read-Host “What is the ticket Number?”
        ""
        ""
        $CurrentDate = get-date -format ddMMMyy
        $NameResult = $CurrentDate + $Name
        $ExchangeLocation = Read-Host “What Assumption mailboxes would you like to search? For All type All. If you want to search specific mailboxes input each email address separated by a coma.”
        ""
        ""
        $ExchangeLocation2 = $ExchangeLocation.Split(“,”).Trim()
        $ContentMatchQuery = Read-Host “What email would you like to search for? To search by subject search (Subject:). To search by Email address input the email address.”
        $Name2 = $NameResult + “_purge”

        ## End variables defined

        ## Start compliance search

        New-ComplianceSearch -Name $NameResult -ExchangeLocation $ExchangeLocation2 -ContentMatchQuery $ContentMatchQuery | Out-Null
        Start-ComplianceSearch $NameResult | Out-Null

        While((Get-ComplianceSearch $NameResult).Status -ne “Completed”)
            {
                Write-Host “Please wait for the search to complete….” -ForegroundColor Yellow
                Start-Sleep -Seconds 120
            }

        ## End compliance search


        ## Displays users who received email as well as users who replied to email

        if ($ContentMatchQuery)
            {
	            Write-Host -ForegroundColor Green "Recipients include:"
	            $recips=Get-MessageTrace -SenderAddress $ContentMatchQuery 
	            $recips | ft -AutoSize Received,RecipientAddress,Subject,Status
	            $recips.RecipientAddress -Join " "
	            "End list of users who received this email"
	
	            ""

	            Write-Warning "Contact these users who replied:"
	            $replies=Get-MessageTrace -RecipientAddress $ContentMatchQuery
	            $replies | ft -AutoSize Received,SenderAddress,Subject,Status
	            $replies.SenderAddress -Join ", "
	            "End list of users who replied to this email"
            }

        ## End User display on screen

        ##Checks if file path for save exists

        $path = "C:\Compliance_Search\Recieved"
        $path2 = "C:\Compliance_Search\Respond"

        if(Test-Path -Path $path)
            {
                Write-Host "A CSV file will be created at $path. This folder contains information on users who received the email." -ForegroundColor Yellow
            }
        else
            {
                New-Item -Path $path -ItemType Directory

                Write-Host "Folder for $path have been created. This folder contains information on users who received the email." -ForegroundColor Yellow
            }


        ##End directory creation for Received


        ##Creats CSV Directory in locations listed above


        if(Test-Path -Path $path2)
            {
                Write-Host "A CSV file will be created at $path2. This folder contains information on users who received the email." -ForegroundColor Yellow
            }
        else
            {
                New-Item -Path $path2 -ItemType Directory

                Write-Host "Folder for $path2 have been created. This folder contains information on users who replied to the email." -ForegroundColor Yellow
            }


        ##Ends folder creation

        ##Creates CSV file for users who received and replied to the email

        Get-MessageTrace -SenderAddress $ContentMatchQuery | Export-CSV "C:\Compliance_Search\Recieved\Recieved_$NameResult.csv"

        Get-MessageTrace -RecipientAddress $ContentMatchQuery | Export-CSV "C:\Compliance_Search\Respond\Respond_$NameResult.csv"

        ##Ends CSV file creation

        $validOptions = @("yes", "y", "no", "n")

        do {
                $purge = Read-Host "Please review the results above. Would you like to remove these emails and block the sender? (Yes/No)"
                $purge = $purge.ToLower().Trim()  # Convert input to lowercase and remove leading/trailing spaces
            } 
        until ($purge -in $validOptions)

        if ($purge -in @("yes", "y")) 
            {
                New-ComplianceSearchAction -SearchName $NameResult -Purge -PurgeType softDelete -Confirm:$False | Out-Null

                While((Get-ComplianceSearchAction $Name2).Status -ne “Completed”)
            {
                Write-Host “Please wait for the delete action to complete….” -ForegroundColor Yellow
                Start-Sleep -Seconds 120
            }

        ##Add email address to base sender block policy

        $policy = Get-HostedContentFilterPolicy -Identity "default"
        $blockedSenders = $policy.BlockedSenders

        ##Combine the existing list with the new email address

        $newBlockedSenders = $blockedSenders + $ContentMatchQuery
        $policy.BlockedSenders = $newBlockedSenders
        Set-HostedContentFilterPolicy -Identity "default" -BlockedSenders $newBlockedSenders

        Write-Host "Email address - ${ContentMatchQuery} - added to the Blocked Senders list." -ForegroundColor Green

        Write-Host “The final delete action results are as following:” -ForegroundColor Yellow

        Get-ComplianceSearchAction $Name2 | FL SearchName,Status,Errors,Results

        ##End Deleting email
            } 
        else 
            {
                Go-Phish
            }
            
    
    }

    ## This will let you add a specific email address to the default spam block list without removing emails from mailboxes
    function Stop-PhishSender 
    {

        ## Prompt user for the email address to block. Confirm what is entered is an email address
        do 
            {
                $sender2block = Read-Host "What email address would you like to block?"

                if (-not ($sender2block -as [MailAddress])) 
                    {
                        Write-Host "Invalid email address format. Please enter a valid email address." -ForegroundColor Red
                    }
            }
             
        until ($sender2block -as [MailAddress])

        try 
            {
                ## Retrieve the current hosted content filter policy
                $policy = Get-HostedContentFilterPolicy -Identity "default"
                $blockedSenders = $policy.BlockedSenders

                # Combine the existing list with the new email address
                $newBlockedSenders = $blockedSenders + $sender2block
                $policy.BlockedSenders = $newBlockedSenders

                # Update the hosted content filter policy with the new blocked senders list
                Set-HostedContentFilterPolicy -Identity "default" -BlockedSenders $newBlockedSenders

                Write-Host "Email address - ${sender2block} - added to the Blocked Senders list." -ForegroundColor Green
            }
        catch 
            {
                Write-Host "An error occurred while adding the email address to the Blocked Senders list: $_" -ForegroundColor Red
            }
    }

    ## This is the main function of the program. 
    Function Go-Phish
        {
            "============================================================================================"
            "|                       _____                 ______ _     _     _                         |" 
            "|                      |  __ \                | ___ \ |   (_)   | |                        |"
            "|                      | |  \/ ___    ______  | |_/ / |__  _ ___| |__                      |"
            "|                      | | __ / _ \  |______| |  __/| '_ \| / __| '_ \                     |"
            "|                      | |_\ \ (_) |          | |   | | | | \__ \ | | |                    |"
            "|                       \____/\___/           \_|   |_| |_|_|___/_| |_|                    |"
            "============================================================================================"
            ""
            ""
            ""
            "Welcome to Go-Phish. This program allows you to find and remove phishing emails that are reported by your end users"
            "You can search for the phshing email, remvoe the email, review previous searchs, and perform phishing attacks."
            ""
            ""
            ""
            ""
            "[1] Scan for emails"
            "[2] Block a sender"
            "[3] Review previous scans"
            "[4] Create phishing emails"
            "[Q] Quit"
            ""
            ""
            ""
            $Select = Read-Host "Please select one of the options above."

            If ($Select -eq "1")
                {
                    Get-Phish
                }
            If ($Select -eq "2")
                {
                    Stop-PhishSender
                }
            If ($Select -eq "3") ###FUNCTION NOT CREATED YET!!
                {
                    Show-Phish
                }
            If ($Select -eq "4")
                {
                    Start-Phish
                }
            if ($Select -eq "Q" -or $Select -eq "q")
                {
                    Disconnect-ExchangeOnline -Confirm:$false
                    Break
                }
        }

    ## This function is not completed or tested. It currently only takes user information to create an send an email.
    ## I have not tested it to confirm it works. I also need to update the SMTP server when I test. I would like to
    ## add functions that will create the email VIA HTML so that I can create a folder with pre-made templates. These
    ## templates will need to be edited for use. Provide instructions on github for configuration on these items. 
    Function Start-Phish
        {
            param (
                [string]$FromAddress,
                [string]$ToAddress,
                [string]$Subject,
                [string]$Body
                )
            $FromAddress = Read-Host "Enter the fake sender email address"
            $ToAddress = Read-Host "Enter the recipient email address"
            $Subject = Read-Host "Enter the email subject"
            $Body = Read-Host "Enter the email body"

            $MessageParameters = @{
                From       = $FromAddress
                To         = $ToAddress
                Subject    = $Subject
                Body       = $Body
                SmtpServer = "your.smtp.server.com"  # Replace with your SMTP server address
                }

            Send-MailMessage @MessageParameters
        }

Go-Phish
}
