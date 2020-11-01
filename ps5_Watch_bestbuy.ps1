#This script is meant to check Bestbuy for available PS5s
#It is meant to refresh the page as long as the purchase button on the site is disabled


[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#-----------------navigate to BestBuy's PS5 page and open it-----------------------------

#Webpage variable
$bb = "https://www.bestbuy.com/site/sony-playstation-5-console/6426149.p?skuId=6426149"

#class variable obtained from view source of actual Best Buy webpage
$bbClass = 'btn btn-disabled btn-lg btn-block add-to-cart-button'

#Not used
#$bbId = 'wait-overlay-6426149'


#create an IE variable because Chrome does not come as an object for powershell
$ie = New-Object -ComObject InternetExplorer.Application



# allow the website to be opened and seen
$ie.navigate($bb)
$ie.Visible = $true

#Give the webpage time to fully load
while($ie.Busy -eq $true){
Start-Sleep -Seconds 3
write-host 'Page is still loading...be cool'
#Write-Host 'You may be prompted to accept cookies like 3 times. No big deal'
}


#---------------------------------------------------------------------------------------------------
#------------------check to see if the COMING SOON button is still disabled-------------------------

$bucket = $ie.Document.IHTMLDocument3_getElementsByTagName('button') | ? {$_.textcontent -eq 'Coming Soon'}
#$bucket

$answer = $bucket.textContent
Write-Host ($answer + " is the enemy")


#------tried using INVOKE-WEBREQUEST but it breaks the script during the while loop-------

#Invoke-WebRequest and hold the HTMLWebResponse Object in variable
#$holdpage = Invoke-WebRequest "https://www.bestbuy.com/site/sony-playstation-5-console/6426149.p?skuId=6426149"


#Store the disabled COMING SOON button element as an object
#$disabled=$holdpage.ParsedHtml.body.getElementsByClassName($bbClass)


#used for troubleshooting
#$disabled

#Key in on the text COMING SOON, which would not be there if they had PS5s in stock, and store in a variable
#$comingsoon = $disabled | select textcontent

#$comingsoon = $comingsoon.textContent

#used for troubleshooting
#$comingSoon





#-------REFRESH THE SCREEN-----------------
#---------W-A-R-N-I-N-G-------------
#WARNING: THIS IS THE SAME AS PRESSING F5 PHYSCIALLY ON YOUR LAPTOP
#IT WILL REFRESH ANY AND ALL WEBPAGES YOU HAVE OPEN
#---------W-A-R-N-I-N-G-------------


Write-Host 'True or False describes if the webpage is in the forefront or not. No sweat.'
#This will bring the webpage to the forefront
$wshell = New-Object -ComObject WScript.Shell
$wshell.AppActivate('Sony Playstation 5 Console 3005718 - Best Buy')

while($answer -eq 'Coming Soon'){
    
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wshell.SendKeys("{F5}")
    
    sleep 10

    write-host "page refreshed"
    #echo 'IM IN THE WHILE LOOP'

    $bucket = $ie.Document.IHTMLDocument3_getElementsByTagName('button') | ? {$_.textcontent -eq 'Coming Soon'}
    #$bucket

    $answer = $bucket.textContent
    $answer
   
        

} 

#VICTORY IS YOURS
if ($comingSoon -ne 'Coming Soon') {
        Write-Host "COMING SOON IS DEAD!!! `n BUY! BUY! BUY! `n CLICK THE BUY BUTTON YOU IDIOT!"
        [System.Console]::Beep(1000,2000)
        [System.Console]::Beep(2000,2000)
        [System.Console]::Beep(3000,2000)
        [System.Console]::Beep(4000,2000)
        }




