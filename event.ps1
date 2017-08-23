$now = [system.datetime]
$beforetime = [system.datetime]

#監視対象のアカウント名
$Moniter_Users = @("Administrator","administrator")

#監視対象外のIPアドレス
$Exculde_Host = @("","-","127.0.0.1","192.168.111.10")

#通知するSlack WebHook
$Slack_Url = "https://hooks.slack.com/services/XXXXXXXXXXXXXXXXXXXXX"

$now = Get-Date

#5分間分のログをチェックする。
$beforetime = $now.addseconds(-300)

#Slackへの通知
Function sendSlack($mes){
    $enc = [System.Text.Encoding]::GetEncoding('ISO-8859-1')
    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($mes)

    $notificationPayload = @{ 
        text = $enc.GetString($utf8Bytes);
        username = "WindowsEvent"; 
    }

    Invoke-RestMethod -Uri $Slack_Url -Method Post -Body (ConvertTo-Json $notificationPayload)
}

#セキュリティ　イベントログからイベントID：4624を取得
$eventlist = Get-Eventlog security -after $beforetime | Where-Object {$_.eventid -eq 4624}

foreach($event in $eventlist){
    #$event.TimeGenerated
    
    $flg = $False
    $detail = [string]$event.Message -split "`n"

    $num = 1
    $suspectuser = ""

    foreach($line in $detail){
        #セキュリティIDからアカウント名を取得
        if($line -match "Security ID:"){
            $tmp = $line.split(":")
            $tmp_secid = $tmp[1].trim()

            if($tmp_secid -ne "NULL SID"){
                $sidObj = New-Object System.Security.Principal.SecurityIdentifier($tmp_secid
)
                $user = $sidObj.Translate([System.Security.Principal.NTAccount])

                foreach($chk_user in $Moniter_Users){
                    if($user.value.contains($chk_user)){
                        $principalname = $user.value
                        $flg = $True
                    }
                }
            }
        }

        #イベントログにおけるアカウント名
        if($line -match "Account Name:"){
            $tmp = $line.split(":")
            $tmp_account = $tmp[1].trim()

            if($tmp_account -ne "-"){
                $suspectuser = $tmp_account
            }
        }

        #ログオンID
        if($line -match "Logon ID:"){
            $tmp = $line.split(":")
            $tmp_logonid = $tmp[1].trim()

            if($tmp_logonid -ne "0x0"){
                $logonid = $tmp_logonid
            }
        }

		#アクセス元IPアドレス
        if($line -match "Source Network Address:"){
            $tmp = $line.split(":")
            $src = $tmp[1].trim()
        }

        if($num -eq $detail.Length){
            foreach($hostnm in $Exculde_Host){
                if($src -eq $hostnm){
                    $flg = $false
                }
            }

            if($flg){
                $send_mes = ""

                if(!$principalname.contains($suspectuser)){
                    $send_mes = "SurityID and Username are different.  Suspicious Access!!!!`n`n`n"
                }
                
                #通知内容
                $send_mes = $send_mes + "<<<<<<<  Login Info  >>>>>>>`n`nTime:   " + $event.TimeGenerated + "`nLogonID:    " + $logonid + "`nFrom:   " + $src + "`nAccount:   " + $suspectuser + "`nSecurityID:    " + $principalname +"`n"
                #Slackへの通知
                sendSlack($send_mes)
            }

            break
        }

        $num++
    }
}


