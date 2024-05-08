go build -o build\jsrunner-server.exe
xcopy static build\static /e /i /Y
copy script.html build\script.html
copy config\web.config build\web.config