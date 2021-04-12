function New-HtmlReport {
  [CmdletBinding()]
  
  param (
      $Path = (Get-Location),
      $title,
      $footer
  )
  if (!$date){$date = (Get-Date -format 'yyyyMMdd_HHmm')}
  
  #region HTML Head
  $hea1=@"
<Style> 
.table {
  margin: 0 0 40px 0;
  width: 100%;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2);
  display: table;
}
.row {
  display: table-row;
  background: #f6f6f6;
}
.row:nth-of-type(odd) {
  background: #e9e9e9;
}
.row.header {
  font-weight: 900;
  color: #ffffff;
  background: #ea6153;
}
.row.green {
  background: #27ae60;
}
.row.blue {
  background: #2980b9;
}
body {
  font-family: "Helvetica Neue", Helvetica, Arial;
  font-size: 14px;
  line-height: 20px;
  font-weight: 400;
  color: #3b3b3b;
  -webkit-font-smoothing: antialiased;
  font-smoothing: antialiased;
  background: #2b2b2b;
}

.wrapper {
  margin: 0 auto;
  padding: 40px;
  max-width: 800px;
}

.table {
  margin: 0 0 40px 0;
  width: 100%;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2);
  display: table;
}
@media screen and (max-width: 580px) {
  .table {
    display: block;
  }
}


@media screen and (max-width: 580px) {
  .row {
    padding: 8px 0;
    display: block;
  }
}

.cell {
  padding: 6px 12px;
  display: table-cell;
}
@media screen and (max-width: 580px) {
  .cell {
    padding: 2px 12px;
    display: block;
  }
}
 </style>

"@
$head=@"

<Style> 
.dropdown {
    position: relative;
    display: inline-block;
  }
  
.dropdown-content {
    display: none;
    position: absolute;
    background-color: #f9f9f9;
    min-width: 160px;
    box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2);
    padding: 12px 16px;
    z-index: 1;
  }
  
.dropdown:hover .dropdown-content {
    display: block;
  }

Body {

    font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;

    border-collapse: collapse;

    width: 100%;

}
h2 {
    text-align: center;
    font-family: "Trebuchet MS", Arial, Helvetica, sans-serif

}

td, th {
    position: right;
    border: 1px solid #ddd;
    width: 60%;
    padding: 8px;
    overflow-x:auto

}



tr:nth-child(even){background-color: #f2f2f2;}



tr:hover {background-color: #ddd;}



th {
    width: 60%;
    padding-top: 6px;

    padding-bottom: 12px;

    text-align: left;

    background-color: #4CAF50;

    color: white;

} </style>

"@
  #endregion


  try {
      $csv_PatchesNotFound = Get-ChildItem -Path (Get-Location).Path -Recurse |Where-Object {($_.Name -like "*PatchesNotFound.csv*")} |Select-Object -ExpandProperty Fullname 

      $csv_missingKB = Get-ChildItem -Path (Get-Location).Path -Recurse |Where-Object {($_.Name -like "*-MissingKBs.csv*")} |Select-Object -ExpandProperty Fullname 
  }

  catch {
      Write-Log "ERROR: Unable to get the csv reports under the location of execution. Error: $($error[0])"
  }
  
  $global:html=@()
  $global:html+="<h2>$Title</h2>"
  #Missing KBs fragment
<#>    $global:html += '
<div class="dropdown">
<span>The following KB Articles were reported as not found from Netupdate Clients and was not found under the BMW Library:</span>
<div class="dropdown-content">
<h3>The following KB Articles were reported as not found: </h3>'
$global:html+= Import-Csv -Delimiter ';' -LiteralPath $csv_missingKB |ConvertTo-Html -As Table -Fragment 
$global:html += '
</div>
</div>'</#>
  $global:html += "<h3>The following KB Articles were reported as not found from Netupdate Clients and was not found under the BMW Library: </h3>"
  $global:html+= Import-Csv -Delimiter ';' -LiteralPath $csv_missingKB |ConvertTo-Html -As Table -Fragment

  #All the reported as not found, but actually available under BMW
 <#> $global:html += '
  <div class="dropdown">
  <span>All the reported as not found, but actually available under BMW:</span>
  <div class="dropdown-content">
  <h3>The following KB Articles were found under BMW: </h3>'
  $global:html+= Import-Csv -Delimiter ';' -LiteralPath $csv_PatchesNotFound |ConvertTo-Html -As Table -Fragment 
  $global:html += '
  </div>
  </div>'</#>

  $global:html += "<h3>All the reported as not found, but actually available under BMW: </h3>"
  $global:html+= Import-Csv -Delimiter ';' -LiteralPath $csv_PatchesNotFound |ConvertTo-Html -As Table -Fragment
  
  if ($footer){
      $global:html+= $footer #|ConvertTo-Html -As Table -Fragment
  }
  $htmlPath="$path\$($title.replace(' ','-')).html"
  
  ConvertTo-Html -Title $title -Body $html -Head $head  |out-file $htmlPath.ToString()
}
 
New-HtmlReport -title "Not Found MS Article IDs"