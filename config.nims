
# Only support x64 atm
task debugbuild, "build project with debug statements":
    exec "nim c -o:gwdebug.dll -f -d=mingw --passL:-Wl,--dynamicbase --app=lib --nomain --cpu=amd64 injector.nim"
    exec "nim c -d=mingw testdllexec.nim"

task build, "build project":
    exec "nim c -o:gw.dll -f -d=mingw -d:zima --passL:-Wl,--dynamicbase --app=lib --nomain --cpu=amd64 injector.nim"
    exec "nim c -d=mingw -d:zima testdllexec.nim"