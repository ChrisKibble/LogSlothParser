$docPages = Get-ChildItem $PSScriptRoot\..\Docs -Include *.md -Recurse | Select-Object -ExpandProperty Name


Describe "Test Doc Pages" { 

    It "Testing Links in <_>" -TestCases $docPages {
        $mdFile = Join-Path $PSScriptRoot\..\Docs -ChildPath $_
        $docData = Get-Content $mdFile -Raw
        $mdLinks = [regex]::New("(?sm)\[.*?\]\((.*?)\)").Matches($docData)
        $allPathsValid = $true
        ForEach($link in $mdLinks) {
            $thisLink = $link.groups[1].Value
            If($thisLink -match "http(s|)://*") {
                Try {
                    Invoke-WebRequest $thisLink -ErrorAction Stop
                } Catch {
                    $allPathsValid = $false
                }
            } else {
                "Testing $thisLink in $_" | Out-Host
                $thisLink = Join-Path $PSScriptRoot\..\Docs -ChildPath $thisLink
                Try { 
                    $thisLink = $(Resolve-Path $thisLink -ErrorAction Stop).Path
                } catch {
                    $allPathsValid = $false
                }    
            }
        }
        $allPathsValid | Should -Be $true
    }

}