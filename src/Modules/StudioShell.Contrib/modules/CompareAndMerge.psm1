<#
.SYNOPSIS
Modules related to the compare and merge tools for Visual Studio TFS integration.
#>

Add-Type -TypeDefinition @"
    namespace JustAProgrammer.DevEnv {
        [System.Flags]
        public enum VisualStudioVersion : short {
            //VisualStudio2005 = 0x01,
            VisualStudio2008 = 0x02,
            VisualStudio2010 = 0x04,
            VisualStudio2012 = 0x08,
            All = VisualStudio2008 | VisualStudio2010 | VisualStudio2012
        }
        
        public enum MergeTools : short {
            BuiltIn,
            WinMerge,
            KDiff3,
            SemanticMerge,
            BeyondCompare,
            BeyondComparePro
        }
 
        public class MergeToolInfo {
            public string Command { get; set; }
            public string CompareArgs { get; set; }
            public string MergeArgs { get; set; }
        }
    }
"@
 
$visualStudioRootNode = 'HKCU:\SOFTWARE\Microsoft\VisualStudio'
$diffToolsSubNode = 'TeamFoundation\SourceControl\DiffTools\.*'
$compareSubNode = "$($diffToolsSubNode)\Compare"
$mergeSubNode = "$($diffToolsSubNode)\Merge"
 
$mergeToolTestPaths = New-Object 'System.Collections.Generic.Dictionary[JustAProgrammer.DevEnv.MergeTools,string]'
$mergeToolTestPaths[[JustAProgrammer.DevEnv.MergeTools]::KDiff3] = 'HKLM:\SOFTWARE\KDiff3\diff-ext'
$mergeToolTestPaths[[JustAProgrammer.DevEnv.MergeTools]::WinMerge] = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WinMerge_is1'
if ([System.IntPtr]::Size -eq 4) {
    $mergeToolTestPaths[[JustAProgrammer.DevEnv.MergeTools]::WinMerge] = `
        $mergeToolTestPaths[[JustAProgrammer.DevEnv.MergeTools]::WinMerge].Replace('\Wow6432Node', '')
}
$mergeToolTestPaths[[JustAProgrammer.DevEnv.MergeTools]::SemanticMerge] = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\SemanticMerge'
$mergeToolTestPaths[[JustAProgrammer.DevEnv.MergeTools]::BeyondCompare] = 'HKLM:\SOFTWARE\Wow6432Node\Scooter Software\Beyond Compare'
 
# Thanks to Naeem Khedaron for these settings http://blog.khedan.com/2009/12/setting-up-and-using-kdiff-in-visual.html
$mergeTools = New-Object 'System.Collections.Generic.Dictionary[JustAProgrammer.DevEnv.MergeTools, JustAProgrammer.DevEnv.MergeToolInfo]'
if (Test-Path $mergeToolTestPaths[[JustAProgrammer.DevEnv.MergeTools]::WinMerge]) {
    $mergeTools[[JustAProgrammer.DevEnv.MergeTools]::WinMerge] = New-Object JustAProgrammer.DevEnv.MergeToolInfo -Property @{
        Command = Join-Path (Get-ItemProperty $mergeToolTestPaths[[JustAProgrammer.DevEnv.MergeTools]::WinMerge] 'InstallLocation').InstallLocation 'WinMergeU.exe';
        CompareArgs = '/x /e /ub /wl /dl %6 /dr %7 %1 %2';
        MergeArgs = '/x /e /ub /wl /dl %6 /dr %7 %1 %2 %4';
    }
}
 
# Thanks to Rory Primrose for these settings http://www.neovolve.com/post/2007/06/19/using-winmerge-with-tfs.aspx
if (Test-Path $mergeToolTestPaths[[JustAProgrammer.DevEnv.MergeTools]::KDiff3]) {
    $mergeTools[[JustAProgrammer.DevEnv.MergeTools]::KDiff3] = New-Object JustAProgrammer.DevEnv.MergeToolInfo -Property @{
        Command = (Get-ItemProperty $mergeToolTestPaths[[JustAProgrammer.DevEnv.MergeTools]::KDiff3] 'diffcommand').diffcommand;
        CompareArgs = '%1 --fname %6 %2 --fname %7';
        MergeArgs = '%3 --fname %8 %2 --fname %7 %1 --fname %6 -o %4';
    }
}
 
# Settings from here: https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=1&cad=rja&ved=0CDIQFjAA&url=http%3A%2F%2Fwww.semanticmerge.com%2Fdocuments%2FSemanticMerge-TFS.pdf&ei=xeJ_UaSnEerI0gGVyoHoDg&usg=AFQjCNGehcC4jVaM4d5IYoqkvTMRcU_rEA&sig2=2-9S5BF7cnYKkSLCwRMNcQ&bvm=bv.45645796,d.dmQ
if (Test-Path $mergeToolTestPaths[[JustAProgrammer.DevEnv.MergeTools]::SemanticMerge]) {
    $mergeTools[[JustAProgrammer.DevEnv.MergeTools]::SemanticMerge] = New-Object JustAProgrammer.DevEnv.MergeToolInfo -Property @{
        Command = Join-Path (Get-ItemProperty $mergeToolTestPaths[[JustAProgrammer.DevEnv.MergeTools]::SemanticMerge] 'InstallLocation').InstallLocation 'semanticmergetool.exe';
        CompareArgs = '-s=%1 -d=%2';
        MergeArgs = '-s=%1 -d=%2 -b=%3 -r=%4 -sn=%6 -dn=%7 -bn=%8 -emt=default -edt=default';
    }
}
 
# Settings from here: http://www.scootersoftware.com/support.php?zz=kb_vcs#tfs
if (Test-Path $mergeToolTestPaths[[JustAProgrammer.DevEnv.MergeTools]::BeyondCompare]) {
    $mergeTools[[JustAProgrammer.DevEnv.MergeTools]::BeyondCompare] = New-Object JustAProgrammer.DevEnv.MergeToolInfo -Property @{
        Command = (Get-ItemProperty $mergeToolTestPaths[[JustAProgrammer.DevEnv.MergeTools]::BeyondCompare] 'ExePath').ExePath;
        CompareArgs = '%1 %2 /title1=%6 /title2=%7';
        MergeArgs = '%1 %2 /savetarget=%4 /title1=%6 /title2=%7';
    }
    #BeyondCompare Pro supports 3 way merge
    #TODO: Figure out a way to detect Pro Support
    $mergeTools[[JustAProgrammer.DevEnv.MergeTools]::BeyondComparePro] = New-Object JustAProgrammer.DevEnv.MergeToolInfo -Property @{
        Command = (Get-ItemProperty $mergeToolTestPaths[[JustAProgrammer.DevEnv.MergeTools]::BeyondCompare] 'ExePath').ExePath;
        CompareArgs = '%1 %2 /title1=%6 /title2=%7';
        MergeArgs = '%1 %2 %3 %4 /title1=%6 /title2=%7 /title3=%8 /title4=%9';
    }
}
 
function Get-VisualStudioInternalVersions {
    <#
    .SYNOPSIS 
      Gets the internal Visual Studio version numbers (e.g. 2010 = 10.0)
    .PARAMETER  VisualStudioVersion
     The version(s) of Visual Studio get the internal versions for
     
    #>
    [CmdletBinding()]
    param(
        [JustAProgrammer.DevEnv.VisualStudioVersion] $VisualStudioVersion = [JustAProgrammer.DevEnv.VisualStudioVersion]::All
    )
    if (($VisualStudioVersion -band [JustAProgrammer.DevEnv.VisualStudioVersion]::VisualStudio2008) -eq [JustAProgrammer.DevEnv.VisualStudioVersion]::VisualStudio2008) {
        Write-Output '9.0'
    }
    if (($VisualStudioVersion -band [JustAProgrammer.DevEnv.VisualStudioVersion]::VisualStudio2010) -eq [JustAProgrammer.DevEnv.VisualStudioVersion]::VisualStudio2010) {
        Write-Output '10.0'
    }
    if (($VisualStudioVersion -band [JustAProgrammer.DevEnv.VisualStudioVersion]::VisualStudio2012) -eq [JustAProgrammer.DevEnv.VisualStudioVersion]::VisualStudio2012) {
        Write-Output '11.0'
    }
}
 
function Remove-VisualStudioMergeTool {
    <#
    .SYNOPSIS 
      Sets the merge tool for all Visual Studio Versions
    .PARAMETER  MergeTool
     The merge tool to use.
    .PARAMETER  VisualStudioVersion
     The version(s) of Visual Studio to set the merge tool for
    .EXAMPLE
     
    #>
    [CmdletBinding()]
    param(
        [JustAProgrammer.DevEnv.VisualStudioVersion] $VisualStudioVersion = [JustAProgrammer.DevEnv.VisualStudioVersion]::All
    )
    Get-VisualStudioInternalVersions $VisualStudioVersion | % {
        $versionDiffNode = "$($visualStudioRootNode)\$($_)\$($diffToolsSubNode)";
        Write-Debug "Deleting Registry key $($versionDiffNode)"
        Remove-Item $versionDiffNode -Force -Recurse | Out-Null
    }
}
 
function Set-VisualStudioMergeTool {
    <#
    .SYNOPSIS 
      Sets the merge tool for all Visual Studio Versions
    .PARAMETER  MergeT
    ool
     The merge tool to use.
    .PARAMETER  VisualStudioVersion
     The version(s) of Visual Studio to set the merge tool for
    .EXAMPLE
     
    #>
    [CmdletBinding()]
    param(
        [Parameter (Position = 0, Mandatory=$true, HelpMessage = 'The name of the merge tool')][JustAProgrammer.DevEnv.MergeTools] $MergeTool,
        [JustAProgrammer.DevEnv.VisualStudioVersion] $VisualStudioVersion = [JustAProgrammer.DevEnv.VisualStudioVersion]::All
    )
    if ($MergeTool -eq [JustAProgrammer.DevEnv.MergeTools]::BuiltIn ) { return Remove-VisualStudioMergeTool $VisualStudioVersion } 
    if ( -not $mergeTools.Keys.Contains($MergeTool)) { Write-Error "MergeTool `"$($MergeTool)`" not found"; return; }
    Write-Debug "MergeTool $($MergeTool) found at $($mergeTools[$MergeTool].Command)"
    
    Get-VisualStudioInternalVersions $VisualStudioVersion | % {
        $versionCompareNode = "$($visualStudioRootNode)\$($_)\$($compareSubNode)";
        $versionMergeNode = "$($visualStudioRootNode)\$($_)\$($mergeSubNode)";
        New-Item $versionCompareNode -Force | Out-Null
        Set-ItemProperty $versionCompareNode -Name Command -Value $mergeTools[$mergeTool].Command
        Set-ItemProperty $versionCompareNode -Name Arguments -Value $mergeTools[$mergeTool].CompareArgs
        New-Item $versionMergeNode -Force | Out-Null
        Set-ItemProperty $versionMergeNode -Name Command -Value $mergeTools[$mergeTool].Command
        Set-ItemProperty $versionMergeNode -Name Arguments -Value $mergeTools[$mergeTool].MergeArgs
    }
}