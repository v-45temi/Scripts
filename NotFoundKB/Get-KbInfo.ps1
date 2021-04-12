$sourceLink = "https://www.catalog.update.microsoft.com/Search.aspx?q="
$kbs= @("
2506928
2881030
3054886
2589318
2597087
4493174
2445990
2596904
934736
3072305
3004375
2979596
3128043
2553065
2526302
2687456
923618
2526298
2932965
2738315
2526297
2460011
2880505
2863822
907417
2825642
963677
2938807
3002340
2890573
4602298
2529927
2687499
2506014
4601383
20190611
2512715
4052908
4052623
934737
4601380
4601556
963673
3002339
2781514
963671
4019990
3045313
3115475
982726
2607047
981111
977236
981391
3054205
928957
2608658
977238
2553406
963669
963665
981392
981390
977239
3118401
937961
20210112
2716440
3125217
2850064
2526301
3158271
2687469
")
$kbs = ($kbs.split()).trim() -match '\S'
$report = @()
$pattern = "(?s)(?<=\;\')(.*?)(?=>)(.*?)(?=\<\/a\>)"

$regexpattern = [Regex]::new($pattern)

foreach ($kb in $kbs){
    try {
        $web = (Invoke-WebRequest -Uri "$sourceLink$kb" -ErrorAction Stop).Content 
        #$title =(($web.tostring() -split "[`r`n]" | Select-String  (");'>")) -replace ("<a>","") -replace ("</a>","")).trimstart()
        $regexmatches = $regexpattern.Matches($web)
        $title = (($regexmatches.value -replace (">",'')).trimstart()).trimend()
    }
    catch{
        Write-Output "Error while invoke web rebquest: $($error[0])"
        $title = ""
    }
    if ($title.count -gt 1){
        $title = $title -join ";"
    }
    $report += New-Object -TypeName PSObject -Property @{
        KbNumber = $kb;
        Title =  $title
    }
    
}
$date = Get-Date -Format "yyyy-MM-dd_HHmm"
$report |Export-Csv -Path ".\$date-PatchesForOutcomment.csv" -NoTypeInformation -Delimiter  ";" #-Append 