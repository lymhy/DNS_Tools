@echo off
rem dnspick 启动器 —— 唯一菜单入口。
rem 按「逐步收窄」的顺序问三个问题，再把参数拼出来调用 exe：
rem   第1步 模式     这一轮测多深
rem   第2步 端点类型 和哪种 DNS 端点通信（可多选，如 23 = IPv4 UDP + DoH）
rem   第3步 服务器   整个候选列表 / 只测国内 / 只测国外
rem 参数逐步拼接，运行前先把真实命令行打印出来，方便核对。
rem
rem 本文件以 UTF-8 保存，首行切到代码页 65001，因此中文提示在任何系统代码页下都能正常显示。
rem 两点禁忌：不要把 ASCII 括号写进 echo 文本（会被 cmd 当成块结束），
rem 也不要用 «if 条件 set X & goto Y» 的写法（& 后面的命令无条件执行）。
rem 脚本化调用请直接调 exe，例如 dnspick.exe --full --interface "WLAN"
chcp 65001 >nul
setlocal
cd /d "%~dp0"

if not exist dnspick.exe (
    echo [错误] 当前目录没有 dnspick.exe
    echo         请先构建：go build -o dnspick.exe ./cmd/dnspick
    echo.
    pause
    exit /b 1
)

rem 一旦存在自定义列表就自动带上，这样加进 dnspick.yaml 的 DNS 从菜单进去也会被测到。
rem 于是 --servers 就成了对该列表的「筛选」，而不是替换。
set "CFG="
set "CFGSRC=内置默认列表"
if exist dnspick.yaml (
    set "CFG=--config dnspick.yaml"
    set "CFGSRC=dnspick.yaml"
)

:MODE
cls
echo ============================================
echo   dnspick —— 本地宽带 DNS 优选工具
echo ============================================
echo.
echo   候选来源: %CFGSRC%
echo.
echo 第 1 步 / 共 3 步 —— 这一轮想做什么？
echo.
echo   1) 快速测试    约 1 分钟
echo   2) 完整测试    数分钟，额外做递归 / 污染比对 / ECS / TTFB（时长随候选数与网络而定）
echo   3) 只看网卡    列出本机所有网卡及各自的 DNS，不做测速
echo   4) 退出
echo.
set "m="
set /p "m=输入数字后回车 [默认 1]: "
if "%m%"=="" set "m=1"
if "%m%"=="1" goto M_QUICK
if "%m%"=="2" goto M_FULL
if "%m%"=="3" goto LISTIF
if "%m%"=="4" goto END
echo.
echo [警告] 没有这个选项: %m%
echo.
pause
goto MODE

:M_QUICK
set "MODE=快速"
goto PROTO

:M_FULL
set "MODE=完整"
goto PROTO

:PROTO
cls
echo ============================================
echo   dnspick —— 第 2 步 / 共 3 步 —— 端点类型
echo ============================================
echo.
echo   模式: %MODE%
echo.
echo   1) 默认       IPv4 UDP + DoH，IPv6 自检通过时自动加上 IPv6 UDP
echo   2) IPv4 UDP   只测经典 53 端口
echo   3) DoH        只测 DNS over HTTPS，走 443
echo   4) DoT        只测 DNS over TLS，走 853
echo   5) IPv6 UDP   只测 IPv6 的 53 端口，需要 IPv6 可用
echo   6) 全部       IPv4 + IPv6 + DoH + DoT
echo   9) 返回上一步
echo.
echo   可多选：例如 23 = IPv4 UDP + DoH，246 = IPv4 UDP + DoT + 全部。
echo   含义提示：「默认」就是 1，等于 2 + 3 + 5；选定即「只测这些」，
echo   所以选了 DoT 的这一轮不会再出现 UDP 结果；没有 DoH / DoT
echo   地址的服务器在该轮里不会有端点。
echo.
set "p="
set /p "p=输入数字，可多个，回车确认 [默认 1]: "
if "%p%"=="" set "p=1"
set "p=%p: =%"

set "P_UDP="
set "P_UDP6="
set "P_DOH="
set "P_DOT="
set "HIT="
set "PROTO="

if "%p%"=="9" goto MODE
if "%p%"=="1" goto PROTO_DONE

:PARSE
if "%p%"=="" goto PARSE_END
set "ch=%p:~0,1%"
set "p=%p:~1%"
if "%ch%"=="2" (set "P_UDP=1" & set "HIT=1")
if "%ch%"=="3" (set "P_DOH=1" & set "HIT=1")
if "%ch%"=="4" (set "P_DOT=1" & set "HIT=1")
if "%ch%"=="5" (set "P_UDP6=1" & set "HIT=1")
if "%ch%"=="6" (set "P_UDP=1" & set "P_UDP6=1" & set "P_DOH=1" & set "P_DOT=1" & set "HIT=1")
goto PARSE
:PARSE_END
if not defined HIT goto PROTO_BAD

:PROTO_DONE
set "PROTO="
if defined P_UDP  set "PROTO=%PROTO%,udp"
if defined P_UDP6 set "PROTO=%PROTO%,udp6"
if defined P_DOH  set "PROTO=%PROTO%,doh"
if defined P_DOT  set "PROTO=%PROTO%,dot"
if defined PROTO set "PROTO=--protocol %PROTO:~1%"
goto TARGET

:PROTO_BAD
echo.
echo [警告] 选项无法识别，可用 1-6，且可组合，例如 23。
echo.
pause
goto PROTO

:TARGET
cls
echo ============================================
echo   dnspick —— 第 3 步 / 共 3 步 —— 服务器范围
echo ============================================
echo.
echo   模式: %MODE%
if defined PROTO echo   端点: %PROTO%
if not defined PROTO echo   端点: 默认
echo   候选来源: %CFGSRC%
echo.
echo   1) 当前列表    测试候选列表里的全部服务器
echo   2) 只测国内    在当前列表里筛选国内公共 DNS
echo   3) 只测国外    在当前列表里筛选国外公共 DNS
echo   9) 返回上一步
echo.
echo   说明: 2 / 3 是对「当前列表」做筛选，列表里没有的地址不会被凭空加进来；
echo         若列表里一个都不匹配，这一轮就没有可测端点。当前列表就是
echo         上面「候选来源」指出的那份，改 dnspick.yaml 即改这里的内容。
echo.
set "t="
set "SRV="
set /p "t=输入数字后回车 [默认 1]: "
if "%t%"=="" set "t=1"
if "%t%"=="1" goto RUN
if "%t%"=="2" goto T_CN
if "%t%"=="3" goto T_INTL
if "%t%"=="9" goto PROTO
echo.
echo [警告] 没有这个选项: %t%
echo.
pause
goto TARGET

:T_CN
set "SRV=--servers 223.5.5.5,223.6.6.6,119.29.29.29,119.28.28.28,114.114.114.114,180.76.76.76"
goto RUN

:T_INTL
set "SRV=--servers 8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1,9.9.9.9"
goto RUN

:RUN
set "ARGS=%CFG%"
if not "%PROTO%"=="" set "ARGS=%ARGS% %PROTO%"
if not "%SRV%"=="" set "ARGS=%ARGS% %SRV%"
if "%MODE%"=="完整" set "ARGS=%ARGS% --full"

echo.
echo ============================================
echo   即将执行: dnspick.exe %ARGS%
echo ============================================
echo.
dnspick.exe %ARGS%
goto DONE

:LISTIF
rem 这里刻意不加 --interface：没指定网卡时 exe 自己会问。
dnspick.exe --list-interfaces
goto DONE

:DONE
echo.
echo ============================================
echo   结束。结果已存为当前目录下的 dnspick-result-*.txt
echo   想再测一次，请再次双击 dnspick.bat。
echo ============================================
echo.
pause
goto END

:END
endlocal
exit /b 0